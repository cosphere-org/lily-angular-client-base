import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './mediaitems.models';
export declare class MediaitemsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List MediaItems
     * -------------
     *
     * List MediaItems
     */
    bulkReadMediaitems(params: X.BulkReadMediaitemsQuery): DataState<X.BulkReadMediaitemsResponseEntity[]>;
    bulkReadMediaitems2(params: X.BulkReadMediaitemsQuery): Observable<X.BulkReadMediaitemsResponseEntity[]>;
    /**
     * Remove MediaItem
     * -------------
     *
     * Remove MediaItem instance.
     */
    deleteMediaitem(mediaitemId: any, params: X.DeleteMediaitemQuery): Observable<X.DeleteMediaitemResponse>;
    /**
     * Read MediaItem
     * -------------
     *
     * Read MediaItem
     */
    readMediaitem(mediaitemId: any): DataState<X.ReadMediaitemResponse>;
    readMediaitem2(mediaitemId: any): Observable<X.ReadMediaitemResponse>;
    /**
     * Read By Process Id
     * -------------
     *
     * Read MediaItem by Process Id
     */
    readMediaitemByProcessId(processId: any): DataState<X.ReadMediaitemByProcessIdResponse>;
    readMediaitemByProcessId2(processId: any): Observable<X.ReadMediaitemByProcessIdResponse>;
    /**
     * Read or Create MediaItem
     * -------------
     *
     * Read or Create MediaItem instance.
     */
    readOrCreateMediaitem(body: X.ReadOrCreateMediaitemBody): Observable<X.ReadOrCreateMediaitemResponse>;
    /**
     * Update MediaItem
     * -------------
     *
     * Update MediaItem instance.
     */
    updateMediaitem(mediaitemId: any, body: X.UpdateMediaitemBody): Observable<X.UpdateMediaitemResponse>;
    /**
     * Update MediaItem Representation
     * -------------
     *
     * Update given MediaItem with only the fields which are decided externally (using external services). Fields like: - `web_representations` - `thumbnail_uri` - `meta` - `text` All of those fields are computed in smarter way in order to make the MediaItem way better in a semantic sense. Those fields are perceived as the `representation` of a given MediaItem since they contains information about how to display a given MediaItem, how to understand it etc. It goes beyond the simple abstract data oriented representation (uri, extension etc.).
     */
    updateMediaitemRepresentation(mediaitemId: any, body: X.UpdateMediaitemRepresentationBody): Observable<X.UpdateMediaitemRepresentationResponse>;
}
