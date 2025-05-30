<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use Pterodactyl\Facades\Activity;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\View\View;
use LaravelWebauthn\Facades\Webauthn;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;

class LoginController extends AbstractLoginController
{
    /**
     * @var string
     */
    private const SESSION_PUBLICKEY_REQUEST = 'webauthn.publicKeyRequest';

    private CacheRepository $cache;
    private UserRepositoryInterface $repository;
    private ViewFactory $view;

    /**
     * LoginController constructor.
     */
    public function __construct(
        AuthManager $auth,
        Repository $config,
        CacheRepository $cache,
        UserRepositoryInterface $repository,
        ViewFactory $view
    ) {
        parent::__construct($auth, $config);

        $this->cache = $cache;
        $this->repository = $repository;
        $this->view = $view;
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component.  React will take over at this point and
     * turn the login area into a SPA.
     */
    public function index(): View
    {
        return $this->view->make('templates/auth.core');
    }

    /**
     * Handle a login request to the application.
     *
     * @return \Illuminate\Http\JsonResponse|void
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        $username = $request->input('user');
        $useColumn = $this->getField($username);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        try {
            /** @var \Pterodactyl\Models\User $user */
            $user = $this->repository->findFirstWhere([[$useColumn, '=', $username]]);
        } catch (RecordNotFoundException $exception) {
            $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceed to the next step in the login process.
        if (!password_verify($request->input('password'), $user->password)) {
            $this->sendFailedLoginResponse($request, $user);
        }

        $webauthnKeys = $user->webauthnKeys()->get();
        $token = Str::random(64);
        if (($webauthnKeys->count()) > 0) {
            $this->cache->put($token, $user->id, CarbonImmutable::now()->addMinutes(5));
            $publicKey = Webauthn::prepareAssertion($user);
            $request->session()->put(self::SESSION_PUBLICKEY_REQUEST, $publicKey);
            $request->session()->save();
            $methods = ['webauthn'];
            if ($user->use_totp) {
                $methods[] = 'totp';
            }

            return new JsonResponse([
                'complete' => false,
                'methods' => $methods,
                'confirmation_token' => $token,
                'webauthn' => [
                    'public_key' => $publicKey,
                ],
            ]);
        } else if ($user->use_totp) {
            $this->cache->put($token, $user->id, CarbonImmutable::now()->addMinutes(5));

            return new JsonResponse([
                'complete' => false,
                'methods' => ['totp'],
                'confirmation_token' => $token,
            ]);
        }

        $this->auth->guard()->login($user, true);

        Activity::event('auth:checkpoint')->withRequestMetadata()->subject($user)->log();

        $request->session()->put('auth_confirmation_token', [
            'user_id' => $user->id,
            'token_value' => $token,
            'expires_at' => CarbonImmutable::now()->addMinutes(5),
        ]);
        $this->sendLoginResponse($user, $request);
        return new JsonResponse([
            'data' => [
                'complete' => true,
                'methods' => [],
                'confirmation_token' => $token,
            ],
        ]);
    }
}
