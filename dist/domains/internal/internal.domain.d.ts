import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import * as X from './internal.models';
export declare class InternalDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Clear all Entries for a given User
     * -------------
     *
     * Internal view enabling one to clean up all database entries for a specific `user_id`. It must be of the utmost importance that this endpoint would not be available on the production system.
     */
    deleteEntriesForUser(userId: any): Observable<X.DeleteEntriesForUserResponse>;
}
