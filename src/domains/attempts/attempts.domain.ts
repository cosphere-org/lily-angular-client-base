/**
 * Attempts Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './attempts.models';

@Injectable()
export class AttemptsDomain {
    constructor(private client: ClientService) {}

    /**
     * Update Attempt
     * -------------
     *
     * Update existing Attempt with new cells and / or style.
     */
    public updateAttempt(attemptId: any, body: X.UpdateAttemptBody): Observable<X.UpdateAttemptResponse> {
        return this.client
            .put<X.UpdateAttemptResponse>(`/recall/attempts/${attemptId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Attempt
     * -------------
     *
     * Create Attempt which is a reflection of someone's knowledge regarding a given Card.
     */
    public createAttempt(body: X.CreateAttemptBody): Observable<X.CreateAttemptResponse> {
        return this.client
            .post<X.CreateAttemptResponse>('/recall/attempts/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Attempts By Card
     * -------------
     *
     * List Attempts for a specific Card given by its Id.
     */
    public bulkReadAttemptsByCards(cardId: any): DataState<X.BulkReadAttemptsByCardsResponse> {
        return this.client.getDataState<X.BulkReadAttemptsByCardsResponse>(`/recall/attempts/by_card/${cardId}`);
    }

}