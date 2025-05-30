<?php

namespace Pterodactyl\Http\Controllers\Api\Client;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use LaravelWebauthn\Facades\Webauthn;
use LaravelWebauthn\Models\WebauthnKey;
use Webauthn\PublicKeyCredentialCreationOptions;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Pterodactyl\Transformers\Api\Client\WebauthnKeyTransformer;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\PublicKeyCredentialSource;

class WebauthnController extends ClientApiController
{
    private const SESSION_PUBLICKEY_CREATION = 'webauthn.publicKeyCreation';

    /**
     * Fetch the registered WebAuthn keys for the authenticated user.
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function index(Request $request): array
    {
        return $this->fractal->collection(WebauthnKey::query()->where('user_id', '=', $request->user()->id)->get())
            ->transformWith($this->getTransformer(WebauthnKeyTransformer::class))
            ->toArray();
    }

    /**
     * Initiates the WebAuthn registration process.
     */
    public function register(Request $request): JsonResponse
    {
        if (!Webauthn::canRegister($request->user())) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.cannot_register_new_key'),
                ],
            ], JsonResponse::HTTP_FORBIDDEN);
        }

        try {
            // Generate the WebAuthn registration options for the user
            $publicKey = Webauthn::prepareAttestation($request->user());
            $request->session()->put(self::SESSION_PUBLICKEY_CREATION, $publicKey);
            $request->session()->save();

            return new JsonResponse([
                'public_key' => $publicKey,
            ]);
        } catch (Exception $e) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.registration_failed'),
                ],
            ], JsonResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Finalizes the WebAuthn registration process after the user completes the registration.
     *
     * @return array|JsonResponse
     */
    public function create(Request $request)
    {
        if (!Webauthn::canRegister($request->user())) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.cannot_register_new_key'),
                ],
            ], JsonResponse::HTTP_FORBIDDEN);
        }

        if ($request->input('register') === null) {
            throw new BadRequestHttpException('Missing register data in request body.');
        }

        if ($request->input('name') === null) {
            throw new BadRequestHttpException('Missing name in request body.');
        }

        try {
            // Retrieve the publicKey stored in session during registration
            $publicKey = $request->session()->pull(self::SESSION_PUBLICKEY_CREATION);

            if (!$publicKey instanceof PublicKeyCredentialCreationOptions) {
                throw new ModelNotFoundException(trans('webauthn::errors.create_data_not_found'));
            }

            // Complete registration and store the WebAuthn key
            $webauthnKey = Webauthn::validateAttestation(
                $request->user(),
                json_decode($request->input('register'), true),
                $request->input('name'),
            );

            return $this->fractal->item($webauthnKey)
                ->transformWith($this->getTransformer(WebauthnKeyTransformer::class))
                ->toArray();
        } catch (ModelNotFoundException $e) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.create_data_not_found'),
                ],
            ], JsonResponse::HTTP_NOT_FOUND);
        } catch (Exception $e) {
            return new JsonResponse([
                'error' => [
                    'message' => "Smoll issue" . $e->getMessage(),
                ],
            ], JsonResponse::HTTP_FORBIDDEN);
        }
    }

    /**
     * Deletes a WebAuthn key for the authenticated user.
     */
    public function deleteKey(Request $request, int $webauthnKeyId): JsonResponse
    {
        try {
            // Find the WebAuthn key by ID and delete it
            WebauthnKey::query()
                ->where('user_id', $request->user()->getAuthIdentifier())
                ->findOrFail($webauthnKeyId)
                ->delete();

            return new JsonResponse([
                'deleted' => true,
                'id' => $webauthnKeyId,
            ]);
        } catch (ModelNotFoundException $e) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.object_not_found'),
                ],
            ], JsonResponse::HTTP_NOT_FOUND);
        } catch (Exception $e) {
            return new JsonResponse([
                'error' => [
                    'message' => trans('webauthn::errors.deletion_failed'),
                ],
            ], JsonResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
