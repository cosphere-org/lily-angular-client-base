/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Subscription Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './subscriptions.models';

@Injectable()
export class SubscriptionsDomain {
    constructor(private client: ClientService) {}

    /**
     * Request a subscription change
     * -------------
     *
     * Whenever the user wants to change her subscription it must happen through this endpoint. It's still possible that the subscription will change without user asking for it, but that can happen when downgrading due to missing payment.
     */
    public changeSubscription(body: X.ChangeSubscriptionBody): Observable<X.ChangeSubscriptionResponse> {
        return this.client
            .put<X.ChangeSubscriptionResponse>('/payments/subscription/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

}