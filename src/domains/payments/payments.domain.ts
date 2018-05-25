/**
 * Payments Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './payments.models';

@Injectable()
export class PaymentsDomain {
    constructor(private client: ClientService) {}

    /**
     * Update the status of a given Payment
     * -------------
     *
     * Update the Payment instance identified by the `session_id`. This command is for external use only therefore it doesn't expose internal ids of the payments but rather session id.
     */
    public updatePaymentStatus(body: X.UpdatePaymentStatusBody): Observable<X.UpdatePaymentStatusResponse> {
        return this.client
            .post<X.UpdatePaymentStatusResponse>('/payments/(?P<session_id>[\w\-]+)', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}