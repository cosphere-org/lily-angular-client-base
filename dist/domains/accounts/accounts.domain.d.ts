import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './accounts.models';
export declare class AccountsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Activate Account
     * -------------
     *
     * Activate Account by decoding the `code` which contains the confirmation off the intent and was signed by the user itself.
     */
    activateAccount(body: X.ActivateAccountBody): Observable<X.ActivateAccountResponse>;
    /**
     * Bulk Read Mentors' Account
     * -------------
     *
     * Enable one to Read all available Mentor accounts
     */
    bulkReadAccounts(params: X.BulkReadAccountsQuery): DataState<X.BulkReadAccountsResponseEntity[]>;
    bulkReadAccounts2(params: X.BulkReadAccountsQuery): Observable<X.BulkReadAccountsResponseEntity[]>;
    /**
     * Change Password
     * -------------
     *
     * Enables one to change one's password for an authenticated user.
     */
    changePassword(body: X.ChangePasswordBody): Observable<X.ChangePasswordResponse>;
    /**
     * Create Account
     * -------------
     *
     * Creates User and Account if provided data are valid.
     */
    createAccount(body: X.CreateAccountBody): Observable<X.CreateAccountResponse>;
    /**
     * Read My Account
     * -------------
     *
     * Read my Account data.
     */
    readAccount(): DataState<X.ReadAccountResponse>;
    readAccount2(): Observable<X.ReadAccountResponse>;
    /**
     * Reset Password
     * -------------
     *
     * Enables one to reset her password in case the old one cannot be recalled.
     */
    resetPassword(body: X.ResetPasswordBody): Observable<X.ResetPasswordResponse>;
    /**
     * Send Account Activation Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the Account Activation. Even though the activation email is send automatically during the Sign Up phase one should have a way to send it again in case it was not delivered.
     */
    sendAccountActivationEmail(body: X.SendAccountActivationEmailBody): Observable<X.SendAccountActivationEmailResponse>;
    /**
     * Send Reset Password Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the real Reset Password operation.
     */
    sendResetPasswordEmail(body: X.SendResetPasswordEmailBody): Observable<X.SendResetPasswordEmailResponse>;
    /**
     * Update My Account
     * -------------
     *
     * Update my Account data.
     */
    updateAccount(body: X.UpdateAccountBody): Observable<X.UpdateAccountResponse>;
}
