/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Contact Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './contacts.models';

@Injectable()
export class ContactsDomain {
    constructor(private client: ClientService) {}

    /**
     * Create Anonymous Contact Attempt
     * -------------
     *
     * Enables one to send messages to CoSphere's support even if the sender is not authenticated.
     */
    public createAnonymousContactAttempt(body: X.CreateAnonymousContactAttemptBody): Observable<X.CreateAnonymousContactAttemptResponse> {
        return this.client
            .post<X.CreateAnonymousContactAttemptResponse>('/contacts/anonymous/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Send Authenticated Contact Message
     * -------------
     *
     * Send the Contact Message immediately since it's already for an existing and authenticated user.
     */
    public sendAuthenticatedContactMessage(body: X.SendAuthenticatedContactMessageBody): Observable<X.SendAuthenticatedContactMessageResponse> {
        return this.client
            .post<X.SendAuthenticatedContactMessageResponse>('/contacts/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Verify the contact attempt
     * -------------
     *
     * Verify the correctness of provided verification code and send the message to the CoSphere's support. This mechanism is used for anonymous users only.
     */
    public verifyAnonymousContactAttempt(body: X.VerifyAnonymousContactAttemptBody): Observable<X.VerifyAnonymousContactAttemptResponse> {
        return this.client
            .post<X.VerifyAnonymousContactAttemptResponse>('/contacts/anonymous/verify/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}