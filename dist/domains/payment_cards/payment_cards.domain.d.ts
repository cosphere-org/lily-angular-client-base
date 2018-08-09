import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './payment_cards.models';
export declare class PaymentCardsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Mark a given Payment Card as a default one
     * -------------
     *
     * Enables the the User to mark a specific Payment Card as a default one, meaning that it will be used for all upcoming payments. Marking Payment Card as a default one automatically leads to the unmarking of any Payment Card which was default one before the invocation of the command.
     */
    asDefaultMarkPaymentcard(paymentCardId: any): Observable<X.AsDefaultMarkPaymentcardResponse>;
    /**
     * List all Payment Cards belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Payment Cards which were added by him / her. Among all returned Payment Cards there must be one and only one which is marked as **default**.
     */
    bulkReadPaymentcards(): DataState<X.BulkReadPaymentcardsResponseEntity[]>;
    bulkReadPaymentcards2(): Observable<X.BulkReadPaymentcardsResponseEntity[]>;
    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on. Using the optional `mark_as_default` field one can mark just created Payment Card as the default one.
     */
    createPaymentcard(body: X.CreatePaymentcardBody): Observable<X.CreatePaymentcardResponse>;
    /**
     * Remove a given Payment Card belonging to a given user
     * -------------
     *
     * Enables the the User to remove a specific Payment Card which were added by him / her. Payment Card can be removed only if it's not a default one.
     */
    deletePaymentcard(paymentCardId: any): Observable<X.DeletePaymentcardResponse>;
    /**
     * Pay using the default Payment Card
     * -------------
     *
     * User is allowed only to perform payments against her default Payment Card. In other words on order to use a given Payment Card one has to mark is as default. Also one is not allowed to perform such payments freely and therefore we expect to get a `payment_token` inside which another piece of our system encoded allowed sum to be paid.
     */
    payWithDefaultPaymentCard(body: X.PayWithDefaultPaymentCardBody): Observable<X.PayWithDefaultPaymentCardResponse>;
    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on
     */
    renderPaymentCardWidget(): DataState<X.RenderPaymentCardWidgetResponse>;
    renderPaymentCardWidget2(): Observable<X.RenderPaymentCardWidgetResponse>;
}
