/**
 * Attempt Stats Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './attempt_stats.models';

@Injectable()
export class AttemptStatsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Attempt Stats
     * -------------
     *
     * List Attempt Stats by filtering existing ones.
     */
    public bulkReadAttemptstats(params: X.BulkReadAttemptstatsQuery): DataState<X.BulkReadAttemptstatsResponse> {
        return this.client.getDataState<X.BulkReadAttemptstatsResponse>('/recall/attempt_stats/', { params });
    }

    /**
     * Create Attempt Stat
     * -------------
     *
     * Create Attempt Stat which stores information about basis statistics of a particular recall attempt.
     */
    public createAttemptstat(body: X.CreateAttemptstatBody): Observable<X.CreateAttemptstatResponse> {
        return this.client
            .post<X.CreateAttemptstatResponse>('/recall/attempt_stats/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create External Attempt Stat
     * -------------
     *
     * Create External Attempt Stat meaning one which was rendered elsewhere in any of the multiple CoSphere apps.
     */
    public createExternalAttemptStat(body: X.CreateExternalAttemptStatBody): Observable<X.CreateExternalAttemptStatResponse> {
        return this.client
            .post<X.CreateExternalAttemptStatResponse>('/recall/attempt_stats/external/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}