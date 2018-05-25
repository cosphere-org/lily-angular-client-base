/**
 * Focus Records Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './focus_records.models';

@Injectable()
export class FocusRecordsDomain {
    constructor(private client: ClientService) {}

    /**
     * Read Focus Record Summary
     */
    public readFocusRecordSummary(): DataState<X.ReadFocusRecordSummaryResponse> {
        return this.client.getDataState<X.ReadFocusRecordSummaryResponse>('/focus_records/summary/');
    }

    /**
     * Create Focus Record
     */
    public createFocusrecord(body: X.CreateFocusrecordBody): Observable<X.CreateFocusrecordResponse> {
        return this.client
            .post<X.CreateFocusrecordResponse>('/focus_records/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}