import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './contacts.models';
export declare class ContactsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Create Anonymous Contact Attempt
     * -------------
     *
     * Enables one to send messages to CoSphere's support even if the sender is not authenticated.
     */
    createAnonymousContactAttempt(body: X.CreateAnonymousContactAttemptBody): Observable<X.CreateAnonymousContactAttemptResponse>;
    /**
     * Send Authenticated Contact Message
     * -------------
     *
     * Send the Contact Message immediately since it's already for an existing and authenticated user.
     */
    sendAuthenticatedContactMessage(body: X.SendAuthenticatedContactMessageBody): Observable<X.SendAuthenticatedContactMessageResponse>;
    /**
     * Verify the contact attempt
     * -------------
     *
     * Verify the correctness of provided verification code and send the message to the CoSphere's support. This mechanism is used for anonymous users only.
     */
    verifyAnonymousContactAttempt(body: X.VerifyAnonymousContactAttemptBody): Observable<X.VerifyAnonymousContactAttemptResponse>;
}
