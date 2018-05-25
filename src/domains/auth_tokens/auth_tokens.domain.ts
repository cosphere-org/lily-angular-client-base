/**
 * Auth Tokens Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './auth_tokens.models';

@Injectable()
export class AuthTokensDomain {
    constructor(private client: ClientService) {}

    /**
     * Sign In
     * -------------
     *
     * Validates data provided on the input and if successful returns auth token.
     */
    public createAuthToken(body: X.CreateAuthTokenBody): Observable<X.CreateAuthTokenResponse> {
        return this.client
            .post<X.CreateAuthTokenResponse>('/auth/auth_token/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Facebook Auth Token
     */
    public createFacebookBasedAuthToken(body: X.CreateFacebookBasedAuthTokenBody): Observable<X.CreateFacebookBasedAuthTokenResponse> {
        return this.client
            .post<X.CreateFacebookBasedAuthTokenResponse>('/auth/auth_token/facebook/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Mobile Facebook Auth Token
     */
    public createFacebookBasedMobileAuthToken(body: X.CreateFacebookBasedMobileAuthTokenBody): Observable<X.CreateFacebookBasedMobileAuthTokenResponse> {
        return this.client
            .post<X.CreateFacebookBasedMobileAuthTokenResponse>('/auth/auth_token/facebook/mobile/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Google Auth Token
     */
    public createGoogleBasedAuthToken(body: X.CreateGoogleBasedAuthTokenBody): Observable<X.CreateGoogleBasedAuthTokenResponse> {
        return this.client
            .post<X.CreateGoogleBasedAuthTokenResponse>('/auth/auth_token/google/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Mobile Google Auth Token
     */
    public createGoogleBasedMobileAuthToken(body: X.CreateGoogleBasedMobileAuthTokenBody): Observable<X.CreateGoogleBasedMobileAuthTokenResponse> {
        return this.client
            .post<X.CreateGoogleBasedMobileAuthTokenResponse>('/auth/auth_token/google/mobile/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Refresh JWT token
     * -------------
     *
     * Should be used whenever token is close to expiry or if one is requested to refresh the token because for example account type was changed and new token should be requested to reflect that change.
     */
    public updateAuthToken(): Observable<X.UpdateAuthTokenResponse> {
        return this.client
            .put<X.UpdateAuthTokenResponse>('/auth/auth_token/', {})
            .pipe(filter(x => !_.isEmpty(x)));
    }

}