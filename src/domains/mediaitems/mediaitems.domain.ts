/**
 * MediaItems Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './mediaitems.models';

@Injectable()
export class MediaitemsDomain {
    constructor(private client: ClientService) {}

    /**
     * List MediaItems
     * -------------
     *
     * List MediaItems
     */
    public bulkReadMediaitems(params: X.BulkReadMediaitemsQuery): DataState<X.BulkReadMediaitemsResponse> {
        return this.client.getDataState<X.BulkReadMediaitemsResponse>('/mediaitems/', { params });
    }

    /**
     * Remove MediaItem
     * -------------
     *
     * Remove MediaItem instance.
     */
    public deleteMediaitem(mediaitemId: any, params: X.DeleteMediaitemQuery): Observable<X.DeleteMediaitemResponse> {
        return this.client
            .delete<X.DeleteMediaitemResponse>(`/mediaitems/${mediaitemId}`, { params })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read MediaItem
     * -------------
     *
     * Read MediaItem
     */
    public readMediaitem(mediaitemId: any): DataState<X.ReadMediaitemResponse> {
        return this.client.getDataState<X.ReadMediaitemResponse>(`/mediaitems/${mediaitemId}`);
    }

    /**
     * Read By Process Id
     * -------------
     *
     * Read MediaItem by Process Id
     */
    public readMediaitemByProcessId(processId: any): DataState<X.ReadMediaitemByProcessIdResponse> {
        return this.client.getDataState<X.ReadMediaitemByProcessIdResponse>(`/mediaitems/by_process/${processId}`);
    }

    /**
     * Read or Create MediaItem
     * -------------
     *
     * Read or Create MediaItem instance.
     */
    public readOrCreateMediaitem(body: X.ReadOrCreateMediaitemBody): Observable<X.ReadOrCreateMediaitemResponse> {
        return this.client
            .post<X.ReadOrCreateMediaitemResponse>('/mediaitems/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Update MediaItem
     * -------------
     *
     * Update MediaItem instance.
     */
    public updateMediaitem(mediaitemId: any, body: X.UpdateMediaitemBody): Observable<X.UpdateMediaitemResponse> {
        return this.client
            .put<X.UpdateMediaitemResponse>(`/mediaitems/${mediaitemId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Update MediaItem Representation
     * -------------
     *
     * Update given MediaItem with only the fields which are decided externally (using external services). Fields like: - `web_representations` - `thumbnail_uri` - `meta` - `text` All of those fields are computed in smarter way in order to make the MediaItem way better in a semantic sense. Those fields are perceived as the `representation` of a given MediaItem since they contains information about how to display a given MediaItem, how to understand it etc. It goes beyond the simple abstract data oriented representation (uri, extension etc.).
     */
    public updateMediaitemRepresentation(mediaitemId: any, body: X.UpdateMediaitemRepresentationBody): Observable<X.UpdateMediaitemRepresentationResponse> {
        return this.client
            .put<X.UpdateMediaitemRepresentationResponse>(`/mediaitems/${mediaitemId}/representation/`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}