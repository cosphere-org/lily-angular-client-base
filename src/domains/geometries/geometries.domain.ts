/**
 * Geometries Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './geometries.models';

@Injectable()
export class GeometriesDomain {
    constructor(private client: ClientService) {}

    /**
     * List Geometries
     * -------------
     *
     * List Geometries.
     */
    public bulkReadGeometries(params: X.BulkReadGeometriesQuery): DataState<X.BulkReadGeometriesResponse> {
        return this.client.getDataState<X.BulkReadGeometriesResponse>('/grid/geometries/', { params });
    }

    /**
     * Bulk Update Geometries
     * -------------
     *
     * Update in a Bulk list of Geometries.
     */
    public bulkUpdateGeometries(body: X.BulkUpdateGeometriesBody): Observable<X.BulkUpdateGeometriesResponse> {
        return this.client
            .put<X.BulkUpdateGeometriesResponse>('/grid/geometries/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Geometry by Card
     * -------------
     *
     * Read a Geometry entity given the id of Card which is the parent of the Geometry entity.
     */
    public readGeometryByCard(cardId: any): DataState<X.ReadGeometryByCardResponse> {
        return this.client.getDataState<X.ReadGeometryByCardResponse>(`/grid/geometries/by_card/${cardId}`);
    }

    /**
     * Read Graph
     * -------------
     *
     * Render and read Graph made out of all Cards and Links belonging to a given user.
     */
    public readGraph(params: X.ReadGraphQuery): DataState<X.ReadGraphResponse> {
        return this.client.getDataState<X.ReadGraphResponse>('/grid/graphs/', { params });
    }

}