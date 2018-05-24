/**
 * Cards Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * from './cards.models';

@Injectable()
export class CardsDomain {
    constructor(private client: ClientService) {}

    /**
     * Read Card by Id
     * -------------
     *
     * Read Card by `id`.
     */
    public readCard(cardId: any): DataState<ReadCardResponse> {
        return this.client.getDataState<ReadCardResponse>(`/cards/${cardId}`);
    }

    /**
     * Remove Card
     * -------------
     *
     * Remove list of Cards specified by their ids.
     */
    public bulkDeleteCards(params: BulkDeleteCardsQuery): Observable<BulkDeleteCardsResponse> {
        return this.client
            .delete<BulkDeleteCardsResponse>('/cards/', { params })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    public updateCard(cardId: any, body: UpdateCardBody): Observable<UpdateCardResponse> {
        return this.client
            .put<UpdateCardResponse>(`/cards/${cardId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    public createCard(body: CreateCardBody): Observable<CreateCardResponse> {
        return this.client
            .post<CreateCardResponse>('/cards/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Bulk Read Multiple Cards
     * -------------
     *
     * List subset of Cards depending on various filtering flags.
     */
    public bulkReadCards(params: BulkReadCardsQuery): DataState<BulkReadCardsResponse> {
        return this.client.getDataState<BulkReadCardsResponse>('/cards/', { params });
    }

}