/**
 * Paths Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './paths.models';

@Injectable()
export class PathsDomain {
    constructor(private client: ClientService) {}

    /**
     * Delete Paths
     * -------------
     *
     * Endpoint for Deleting multiple Paths.
     */
    public bulkDeletePaths(params: X.BulkDeletePathsQuery): Observable<X.BulkDeletePathsResponse> {
        return this.client
            .delete<X.BulkDeletePathsResponse>('/paths/', { params })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Path
     * -------------
     *
     * Endpoint for Creating Path.
     */
    public createPath(body: X.CreatePathBody): Observable<X.CreatePathResponse> {
        return this.client
            .post<X.CreatePathResponse>('/paths/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Paths
     * -------------
     *
     * List all user's Paths
     */
    public bulkReadPaths(params: X.BulkReadPathsQuery): DataState<X.BulkReadPathsResponse> {
        return this.client.getDataState<X.BulkReadPathsResponse>('/paths/', { params });
    }

    /**
     * Update Path
     * -------------
     *
     * Endpoint for Updating Path.
     */
    public updatePath(pathId: any, body: X.UpdatePathBody): Observable<X.UpdatePathResponse> {
        return this.client
            .put<X.UpdatePathResponse>(`/paths/${pathId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Path
     * -------------
     *
     * Read single Path
     */
    public readPath(pathId: any): DataState<X.ReadPathResponse> {
        return this.client.getDataState<X.ReadPathResponse>(`/paths/${pathId}`);
    }

}