/**
 * Payment Cards Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './payment_cards.models';

@Injectable()
export class PaymentCardsDomain {
    constructor(private client: ClientService) {}

    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on
     */
    public renderPaymentCardWidget(): DataState<X.RenderPaymentCardWidgetResponse> {
        return this.client.getDataState<X.RenderPaymentCardWidgetResponse>('/payments/payment_cards/widget/');
    }

    /**
     * Remove a given Payment Card belonging to a given user
     * -------------
     *
     * Enables the the User to remove a specific Payment Card which were added by him / her. Payment Card can be removed only if it's not a default one.
     */
    public deletePaymentcard(paymentCardId: any): Observable<X.DeletePaymentcardResponse> {
        return this.client
            .delete<X.DeletePaymentcardResponse>(`/payments/payment_cards/${paymentCardId}`)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List all Payment Cards belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Payment Cards which were added by him / her. Among all returned Payment Cards there must be one and only one which is marked as **default**.
     */
    public bulkReadPaymentcards(): DataState<X.BulkReadPaymentcardsResponse> {
        return this.client.getDataState<X.BulkReadPaymentcardsResponse>('/payments/payment_cards/');
    }

    /**
     * Pay using the default Payment Card
     * -------------
     *
     * User is allowed only to perform payments against her default Payment Card. In other words on order to use a given Payment Card one has to mark is as default. Also one is not allowed to perform such payments freely and therefore we expect to get a `payment_token` inside which another piece of our system encoded allowed sum to be paid.
     */
    public payWithDefaultPaymentCard(body: X.PayWithDefaultPaymentCardBody): Observable<X.PayWithDefaultPaymentCardResponse> {
        return this.client
            .post<X.PayWithDefaultPaymentCardResponse>('/payments/payment_cards/pay_with_default/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on. Using the optional `mark_as_default` field one can mark just created Payment Card as the default one.
     */
    public createPaymentcard(body: X.CreatePaymentcardBody): Observable<X.CreatePaymentcardResponse> {
        return this.client
            .post<X.CreatePaymentcardResponse>('/payments/payment_cards/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Mark a given Payment Card as a default one
     * -------------
     *
     * Enables the the User to mark a specific Payment Card as a default one, meaning that it will be used for all upcoming payments. Marking Payment Card as a default one automatically leads to the unmarking of any Payment Card which was default one before the invocation of the command.
     */
    public asDefaultMarkPaymentcard(paymentCardId: any): Observable<X.AsDefaultMarkPaymentcardResponse> {
        return this.client
            .put<X.AsDefaultMarkPaymentcardResponse>(`/payments/payment_cards/${paymentCardId}/mark_as_default/`, {})
            .pipe(filter(x => !_.isEmpty(x)));
    }

}