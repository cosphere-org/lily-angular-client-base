import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './subscriptions.models';
export declare class SubscriptionsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Request a subscription change
     * -------------
     *
     * Whenever the user wants to change her subscription it must happen through this endpoint. It's still possible that the subscription will change without user asking for it, but that can happen when downgrading due to missing payment.
     */
    changeSubscription(body: X.ChangeSubscriptionBody): Observable<X.ChangeSubscriptionResponse>;
}
