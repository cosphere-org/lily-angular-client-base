/**
 * Tasks Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './tasks.models';

@Injectable()
export class TasksDomain {
    constructor(private client: ClientService) {}

    /**
     * List Tasks
     * -------------
     *
     * List tasks
     */
    public bulkReadTasks(params: X.BulkReadTasksQuery): DataState<X.BulkReadTasksResponse> {
        return this.client.getDataState<X.BulkReadTasksResponse>('/tasks/', { params });
    }

    /**
     * List Task Bins
     * -------------
     *
     * List Tasks Bins
     */
    public bulkReadTaskBins(params: X.BulkReadTaskBinsQuery): DataState<X.BulkReadTaskBinsResponse> {
        return this.client.getDataState<X.BulkReadTaskBinsResponse>('/tasks/bins/', { params });
    }

}