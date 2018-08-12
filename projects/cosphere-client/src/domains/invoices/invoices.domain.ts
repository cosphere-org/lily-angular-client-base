/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Invoice Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './invoices.models';

@Injectable()
export class InvoicesDomain {
    constructor(private client: ClientService) {}

    /**
     * List all Invoices belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Invoices which were generated for his Donations or Subscription payments.
     */
    public bulkReadInvoices(): DataState<X.BulkReadInvoicesResponseEntity[]> {
        return this.client.getDataState<X.BulkReadInvoicesResponseEntity[]>('/payments/invoices/', { responseMap: 'invoices', authorizationRequired: true });
    }
    
    public bulkReadInvoices2(): Observable<X.BulkReadInvoicesResponseEntity[]> {
        return this.client.get<X.BulkReadInvoicesResponseEntity[]>('/payments/invoices/', { responseMap: 'invoices', authorizationRequired: true });
    }

    /**
     * Calculate debt for a given user
     * -------------
     *
     * Calculate debt for a given user by searching for the latest unpaid invoice. It returns payment token which can be used in the PAID_WITH_DEFAULT_PAYMENT_CARD command
     */
    public calculateDebt(): DataState<X.CalculateDebtResponse> {
        return this.client.getDataState<X.CalculateDebtResponse>('/payments/invoices/debt/', { authorizationRequired: true });
    }
    
    public calculateDebt2(): Observable<X.CalculateDebtResponse> {
        return this.client.get<X.CalculateDebtResponse>('/payments/invoices/debt/', { authorizationRequired: true });
    }

}