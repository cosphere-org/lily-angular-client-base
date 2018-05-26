/**
 * Links Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './links.models';

@Injectable()
export class LinksDomain {
    constructor(private client: ClientService) {}

    /**
     * Remove Link
     * -------------
     *
     * Remove a Link between two cards.
     */
    public deleteLink(fromCardId: any, toCardId: any): Observable<X.DeleteLinkResponse> {
        return this.client
            .delete<X.DeleteLinkResponse>(`/grid/links/${fromCardId}/${toCardId}`)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read or Create Link
     * -------------
     *
     * Read or Create a Link between two cards.
     */
    public readOrCreateLink(body: X.ReadOrCreateLinkBody): Observable<X.ReadOrCreateLinkResponse> {
        return this.client
            .post<X.ReadOrCreateLinkResponse>('/grid/links/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}