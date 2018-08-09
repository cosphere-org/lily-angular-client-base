import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './payments.models';
export declare class PaymentsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Update the status of a given Payment
     * -------------
     *
     * Update the Payment instance identified by the `session_id`. This command is for external use only therefore it doesn't expose internal ids of the payments but rather session id.
     */
    updatePaymentStatus(body: X.UpdatePaymentStatusBody): Observable<X.UpdatePaymentStatusResponse>;
}
