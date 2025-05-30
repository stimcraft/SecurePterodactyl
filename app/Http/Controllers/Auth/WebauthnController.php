<?php
namespace Pterodactyl\Http\Controllers\Auth;
use Exception;
use Illuminate\Support\Arr;
use LaravelWebauthn\Events\WebauthnRegister;
use LaravelWebauthn\Services\Webauthn\CredentialAssertionValidator;
use LaravelWebauthn\Services\Webauthn\CredentialAttestationValidator;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Pterodactyl\Models\User;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\JsonResponse;
use LaravelWebauthn\Facades\Webauthn;
use Webauthn\PublicKeyCredentialRequestOptions;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Webauthn\Util\Base64;

class WebauthnController extends AbstractLoginController
{
    private const SESSION_PUBLICKEY_REQUEST = 'webauthn.publicKeyRequest';
    private CacheRepository $cache;
    public function __construct(AuthManager $auth, ConfigRepository $config, CacheRepository $cache)
    {
        parent::__construct($auth, $config);
        $this->cache = $cache;
    }
    /**
     * @return JsonResponse|void
     *
     * @throws \Illuminate\Validation\ValidationException
     * @throws \Pterodactyl\Exceptions\DisplayException
     */
    public function auth(Request $request): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->sendLockoutResponse($request);
        }
        $token = $request->input('confirmation_token');
        try {
            /** @var \Pterodactyl\Models\User $user */
            $user = User::query()->findOrFail($this->cache->get($token, 0));
        } catch (ModelNotFoundException $exception) {
            $this->incrementLoginAttempts($request);
            return $this->sendFailedLoginResponse(
                $request,
                null,
                'The authentication token provided has expired, please refresh the page and try again.'
            );
        }
        $this->auth->guard()->onceUsingId($user->id);
        try {
            $publicKey = $request->session()->pull(self::SESSION_PUBLICKEY_REQUEST);
            if (!$publicKey instanceof PublicKeyCredentialRequestOptions) {
                throw new ModelNotFoundException(trans('webauthn::errors.auth_data_not_found'));
            }
            $credentials = json_decode($request->input('data'), true);

            $result =  Webauthn::validateAssertion($request->user(), json_decode($request->input('data'), true));

            if (!$result) {
                return new JsonResponse([
                    'error' => [
                        'message' => 'Nice attempt, you didn\'t pass the challenge.',
                    ],
                ], JsonResponse::HTTP_I_AM_A_TEAPOT);
            }
            $this->cache->delete($token);
            return $this->sendLoginResponse($user, $request);
        } catch (Exception $e) {
            return new JsonResponse([
                'error' => [
                    'message' => $e->getMessage(),
                ],
            ], JsonResponse::HTTP_FORBIDDEN);
        }
    }
    /**
     * Retrieve the input with a string result.
     */
    private function input(Request $request, string $name, string $default = ''): string
    {
        $result = $request->input($name);
        return is_string($result) ? $result : $default;
    }

    private function fixBase64PaddingAndDecode($base64): mixed
    {
        while (strlen($base64) % 4 !== 0) {
            $base64 .= "=";
        }
        $decodedData = base64_decode($base64, true); // true will ensure it returns FALSE on invalid data.
        if ($decodedData === false) {
            throw new Exception("Base64 decoding failed.");
        }
        $decodedArray = json_decode($decodedData, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $decodedArray;
        }
        return $decodedData;
    }
}
