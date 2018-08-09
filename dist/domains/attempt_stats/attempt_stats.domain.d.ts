import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './attempt_stats.models';
export declare class AttemptStatsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Attempt Stats
     * -------------
     *
     * List Attempt Stats by filtering existing ones.
     */
    bulkReadAttemptstats(params: X.BulkReadAttemptstatsQuery): DataState<X.BulkReadAttemptstatsResponse>;
    bulkReadAttemptstats2(params: X.BulkReadAttemptstatsQuery): Observable<X.BulkReadAttemptstatsResponse>;
    /**
     * Create Attempt Stat
     * -------------
     *
     * Create Attempt Stat which stores information about basis statistics of a particular recall attempt.
     */
    createAttemptstat(body: X.CreateAttemptstatBody): Observable<X.CreateAttemptstatResponse>;
    /**
     * Create External Attempt Stat
     * -------------
     *
     * Create External Attempt Stat meaning one which was rendered elsewhere in any of the multiple CoSphere apps.
     */
    createExternalAttemptStat(body: X.CreateExternalAttemptStatBody): Observable<X.CreateExternalAttemptStatResponse>;
}
