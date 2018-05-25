/**
 * Recall Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './recall.models';

@Injectable()
export class RecallDomain {
    constructor(private client: ClientService) {}

    /**
     * Create Recall Session
     * -------------
     *
     * Render Recall Session composed out of the sequence of Cards that should be recalled in a given order. Based on the RecallAttempt stats recommend another Card to recall in order to maximize the recall speed and success rate.
     */
    public createRecallSession(body: X.CreateRecallSessionBody): Observable<X.CreateRecallSessionResponse> {
        return this.client
            .post<X.CreateRecallSessionResponse>('/recall/sessions/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Recall Summary
     * -------------
     *
     * Read summary stats for cards and their recall_score for a given User.
     */
    public readRecallSummary(): DataState<X.ReadRecallSummaryResponse> {
        return this.client.getDataState<X.ReadRecallSummaryResponse>('/recall/summary/');
    }

}