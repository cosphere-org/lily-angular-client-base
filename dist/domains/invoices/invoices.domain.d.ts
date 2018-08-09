import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './invoices.models';
export declare class InvoicesDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List all Invoices belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Invoices which were generated for his Donations or Subscription payments.
     */
    bulkReadInvoices(): DataState<X.BulkReadInvoicesResponseEntity[]>;
    bulkReadInvoices2(): Observable<X.BulkReadInvoicesResponseEntity[]>;
    /**
     * Calculate debt for a given user
     * -------------
     *
     * Calculate debt for a given user by searching for the latest unpaid invoice. It returns payment token which can be used in the PAID_WITH_DEFAULT_PAYMENT_CARD command
     */
    calculateDebt(): DataState<X.CalculateDebtResponse>;
    calculateDebt2(): Observable<X.CalculateDebtResponse>;
}
