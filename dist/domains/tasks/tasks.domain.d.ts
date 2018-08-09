import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './tasks.models';
export declare class TasksDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Tasks
     * -------------
     *
     * List tasks
     */
    bulkReadTasks(params: X.BulkReadTasksQuery): DataState<X.BulkReadTasksResponseEntity[]>;
    bulkReadTasks2(params: X.BulkReadTasksQuery): Observable<X.BulkReadTasksResponseEntity[]>;
    /**
     * List Task Bins
     * -------------
     *
     * List Tasks Bins
     */
    bulkReadTaskBins(params: X.BulkReadTaskBinsQuery): DataState<X.BulkReadTaskBinsResponseEntity[]>;
    bulkReadTaskBins2(params: X.BulkReadTaskBinsQuery): Observable<X.BulkReadTaskBinsResponseEntity[]>;
}
