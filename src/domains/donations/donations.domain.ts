/**
 * Donations Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './donations.models';

@Injectable()
export class DonationsDomain {
    constructor(private client: ClientService) {}

    /**
     * Check if one can attempt a request displaying donation
     * -------------
     *
     * Since we don't want to overflow user with unnecessary requests for him donating we do it in a smarter way using set of heuristics that together help us to answer the following question: "Is it the best moment to ask for the donation?". Currently we use the following heuristics: - is account old enough? - whether user recently donated - whether we attempted recently to request donation from the user - if the user in a good mood (after doing some successful recalls)
     */
    public checkIfCanAttemptDonation(params: X.CheckIfCanAttemptDonationQuery): DataState<X.CheckIfCanAttemptDonationResponse> {
        return this.client.getDataState<X.CheckIfCanAttemptDonationResponse>('/payments/donations/can_attempt/', { params });
    }

    /**
     * Register anonymous donation
     * -------------
     *
     * One can perform a donation payment even if not being an authenticated user. Even in that case we cannot allow full anonymity and we must require at least email address to send information regarding the status of the payment.
     */
    public createAnonymousDonation(body: X.CreateAnonymousDonationBody): Observable<X.CreateAnonymousDonationResponse> {
        return this.client
            .post<X.CreateAnonymousDonationResponse>('/payments/donations/register_anonymous/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Register donation from authenticated user
     * -------------
     *
     * One can perform a donation payment even as an authenticated user.
     */
    public createDonation(body: X.CreateDonationBody): Observable<X.CreateDonationResponse> {
        return this.client
            .post<X.CreateDonationResponse>('/payments/donations/register/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create donation attempt for authenticated user
     * -------------
     *
     * Each Donation Attempt should be followed by creation of Donation Attempt model instance to reflect that fact. It allows one to track how many times we asked a certain user about the donation in order not to overflow that user with them and not to be too aggressive.
     */
    public createDonationattempt(body: X.CreateDonationattemptBody): Observable<X.CreateDonationattemptResponse> {
        return this.client
            .post<X.CreateDonationattemptResponse>('/payments/donations/attempts/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}