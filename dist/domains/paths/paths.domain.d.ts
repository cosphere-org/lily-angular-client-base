import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './paths.models';
export declare class PathsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Delete Paths
     * -------------
     *
     * Endpoint for Deleting multiple Paths.
     */
    bulkDeletePaths(params: X.BulkDeletePathsQuery): Observable<X.BulkDeletePathsResponse>;
    /**
     * List Paths
     * -------------
     *
     * List all user's Paths
     */
    bulkReadPaths(params: X.BulkReadPathsQuery): DataState<X.BulkReadPathsResponseEntity[]>;
    bulkReadPaths2(params: X.BulkReadPathsQuery): Observable<X.BulkReadPathsResponseEntity[]>;
    /**
     * Create Path
     * -------------
     *
     * Endpoint for Creating Path.
     */
    createPath(body: X.CreatePathBody): Observable<X.CreatePathResponse>;
    /**
     * Read Path
     * -------------
     *
     * Read single Path
     */
    readPath(pathId: any): DataState<X.ReadPathResponse>;
    readPath2(pathId: any): Observable<X.ReadPathResponse>;
    /**
     * Update Path
     * -------------
     *
     * Endpoint for Updating Path.
     */
    updatePath(pathId: any, body: X.UpdatePathBody): Observable<X.UpdatePathResponse>;
}
