/**
 * Accounts Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './accounts.models';

@Injectable()
export class AccountsDomain {
    constructor(private client: ClientService) {}

    /**
     * Activate Account
     * -------------
     *
     * Activate Account by decoding the `code` which contains the confirmation off the intent and was signed by the user itself.
     */
    public activateAccount(body: X.ActivateAccountBody): Observable<X.ActivateAccountResponse> {
        return this.client
            .post<X.ActivateAccountResponse>('/auth/activate/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Authenticate a given token
     * -------------
     *
     * Can be called by the API Gateway in order to authenticate every request using provided token and user's account token
     */
    public authenticateUser(body: X.AuthenticateUserBody): Observable<X.AuthenticateUserResponse> {
        return this.client
            .post<X.AuthenticateUserResponse>('/auth/authenticate/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Bulk Read Mentors' Account
     * -------------
     *
     * Enable one to Read all available Mentor accounts
     */
    public bulkReadAccounts(params: X.BulkReadAccountsQuery): DataState<X.BulkReadAccountsResponse> {
        return this.client.getDataState<X.BulkReadAccountsResponse>('/auth/accounts/', { params });
    }

    /**
     * Change Password
     * -------------
     *
     * Enables one to change one's password for an authenticated user.
     */
    public changePassword(body: X.ChangePasswordBody): Observable<X.ChangePasswordResponse> {
        return this.client
            .post<X.ChangePasswordResponse>('/auth/change_password/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Account
     * -------------
     *
     * Creates User and Account if provided data are valid.
     */
    public createAccount(body: X.CreateAccountBody): Observable<X.CreateAccountResponse> {
        return this.client
            .post<X.CreateAccountResponse>('/auth/accounts/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read My Account
     * -------------
     *
     * Read my Account data.
     */
    public readAccount(): DataState<X.ReadAccountResponse> {
        return this.client.getDataState<X.ReadAccountResponse>('/auth/accounts/me/');
    }

    /**
     * Reset Password
     * -------------
     *
     * Enables one to reset her password in case the old one cannot be recalled.
     */
    public resetPassword(body: X.ResetPasswordBody): Observable<X.ResetPasswordResponse> {
        return this.client
            .post<X.ResetPasswordResponse>('/auth/reset_password/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Send Account Activation Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the Account Activation. Even though the activation email is send automatically during the Sign Up phase one should have a way to send it again in case it was not delivered.
     */
    public sendAccountActivationEmail(body: X.SendAccountActivationEmailBody): Observable<X.SendAccountActivationEmailResponse> {
        return this.client
            .post<X.SendAccountActivationEmailResponse>('/auth/send_activation_email/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Send Reset Password Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the real Reset Password operation.
     */
    public sendResetPasswordEmail(body: X.SendResetPasswordEmailBody): Observable<X.SendResetPasswordEmailResponse> {
        return this.client
            .post<X.SendResetPasswordEmailResponse>('/auth/send_reset_password_email/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Update My Account
     * -------------
     *
     * Update my Account data.
     */
    public updateAccount(body: X.UpdateAccountBody): Observable<X.UpdateAccountResponse> {
        return this.client
            .put<X.UpdateAccountResponse>('/auth/accounts/me/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}