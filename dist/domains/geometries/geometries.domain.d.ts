import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './geometries.models';
export declare class GeometriesDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Geometries
     * -------------
     *
     * List Geometries.
     */
    bulkReadGeometries(params: X.BulkReadGeometriesQuery): DataState<X.BulkReadGeometriesResponseEntity[]>;
    bulkReadGeometries2(params: X.BulkReadGeometriesQuery): Observable<X.BulkReadGeometriesResponseEntity[]>;
    /**
     * Bulk Update Geometries
     * -------------
     *
     * Update in a Bulk list of Geometries.
     */
    bulkUpdateGeometries(body: X.BulkUpdateGeometriesBody): Observable<X.BulkUpdateGeometriesResponse>;
    /**
     * Read Geometry by Card
     * -------------
     *
     * Read a Geometry entity given the id of Card which is the parent of the Geometry entity.
     */
    readGeometryByCard(cardId: any): DataState<X.ReadGeometryByCardResponse>;
    readGeometryByCard2(cardId: any): Observable<X.ReadGeometryByCardResponse>;
    /**
     * Read Graph
     * -------------
     *
     * Render and read Graph made out of all Cards and Links belonging to a given user.
     */
    readGraph(params: X.ReadGraphQuery): DataState<X.ReadGraphResponse>;
    readGraph2(params: X.ReadGraphQuery): Observable<X.ReadGraphResponse>;
}
