/**
 * Cards Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './cards.models';

@Injectable()
export class CardsDomain {
    constructor(private client: ClientService) {}

    /**
     * Read Card by Id
     * -------------
     *
     * Read Card by `id`.
     */
    public readCard(cardId: any): DataState<X.ReadCardResponse> {
        return this.client.getDataState<X.ReadCardResponse>(`/cards/${cardId}`);
    }

    /**
     * Remove Card
     * -------------
     *
     * Remove list of Cards specified by their ids.
     */
    public bulkDeleteCards(params: X.BulkDeleteCardsQuery): Observable<X.BulkDeleteCardsResponse> {
        return this.client
            .delete<X.BulkDeleteCardsResponse>('/cards/', { params })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Bulk Read Multiple Cards
     * -------------
     *
     * List subset of Cards depending on various filtering flags.
     */
    public bulkReadCards(params: X.BulkReadCardsQuery): DataState<X.BulkReadCardsResponse> {
        return this.client.getDataState<X.BulkReadCardsResponse>('/cards/', { params });
    }

    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    public updateCard(cardId: any, body: X.UpdateCardBody): Observable<X.UpdateCardResponse> {
        return this.client
            .put<X.UpdateCardResponse>(`/cards/${cardId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    public createCard(body: X.CreateCardBody): Observable<X.CreateCardResponse> {
        return this.client
            .post<X.CreateCardResponse>('/cards/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}