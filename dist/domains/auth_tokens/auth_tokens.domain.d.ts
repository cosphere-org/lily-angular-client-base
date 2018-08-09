import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './auth_tokens.models';
export declare class AuthTokensDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Authorize a given token
     * -------------
     *
     * Can be called by the API Gateway in order to authorize every request using provided token.
     */
    authorizeAuthToken(): Observable<X.AuthorizeAuthTokenResponse>;
    /**
     * Sign In
     * -------------
     *
     * Validates data provided on the input and if successful returns auth token.
     */
    createAuthToken(body: X.CreateAuthTokenBody): Observable<X.CreateAuthTokenResponse>;
    /**
     * Create Facebook Auth Token
     */
    createFacebookBasedAuthToken(body: X.CreateFacebookBasedAuthTokenBody): Observable<X.CreateFacebookBasedAuthTokenResponse>;
    /**
     * Create Mobile Facebook Auth Token
     */
    createFacebookBasedMobileAuthToken(body: X.CreateFacebookBasedMobileAuthTokenBody): Observable<X.CreateFacebookBasedMobileAuthTokenResponse>;
    /**
     * Create Google Auth Token
     */
    createGoogleBasedAuthToken(body: X.CreateGoogleBasedAuthTokenBody): Observable<X.CreateGoogleBasedAuthTokenResponse>;
    /**
     * Create Mobile Google Auth Token
     */
    createGoogleBasedMobileAuthToken(body: X.CreateGoogleBasedMobileAuthTokenBody): Observable<X.CreateGoogleBasedMobileAuthTokenResponse>;
    /**
     * Refresh JWT token
     * -------------
     *
     * Should be used whenever token is close to expiry or if one is requested to refresh the token because for example account type was changed and new token should be requested to reflect that change.
     */
    updateAuthToken(): Observable<X.UpdateAuthTokenResponse>;
}
