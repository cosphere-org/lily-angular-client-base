/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Paths Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

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
            .delete<X.BulkDeletePathsResponse>('/paths/', { params, authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Paths
     * -------------
     *
     * List all user's Paths
     */
    public bulkReadPaths(params: X.BulkReadPathsQuery): DataState<X.BulkReadPathsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadPathsResponseEntity[]>('/paths/', { params, responseMap: 'data', authorizationRequired: true });
    }
    
    public bulkReadPaths2(params: X.BulkReadPathsQuery): Observable<X.BulkReadPathsResponseEntity[]> {
        return this.client.get<X.BulkReadPathsResponseEntity[]>('/paths/', { params, responseMap: 'data', authorizationRequired: true });
    }

    /**
     * Create Path
     * -------------
     *
     * Endpoint for Creating Path.
     */
    public createPath(body: X.CreatePathBody): Observable<X.CreatePathResponse> {
        return this.client
            .post<X.CreatePathResponse>('/paths/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Path
     * -------------
     *
     * Read single Path
     */
    public readPath(pathId: any): DataState<X.ReadPathResponse> {
        return this.client.getDataState<X.ReadPathResponse>(`/paths/${pathId}`, { authorizationRequired: true });
    }
    
    public readPath2(pathId: any): Observable<X.ReadPathResponse> {
        return this.client.get<X.ReadPathResponse>(`/paths/${pathId}`, { authorizationRequired: true });
    }

    /**
     * Update Path
     * -------------
     *
     * Endpoint for Updating Path.
     */
    public updatePath(pathId: any, body: X.UpdatePathBody): Observable<X.UpdatePathResponse> {
        return this.client
            .put<X.UpdatePathResponse>(`/paths/${pathId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

}