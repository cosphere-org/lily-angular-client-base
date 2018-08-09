import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './focus_records.models';
export declare class FocusRecordsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Create Focus Record
     */
    createFocusrecord(body: X.CreateFocusrecordBody): Observable<X.CreateFocusrecordResponse>;
    /**
     * Read Focus Record Summary
     */
    readFocusRecordSummary(): DataState<X.ReadFocusRecordSummaryResponse>;
    readFocusRecordSummary2(): Observable<X.ReadFocusRecordSummaryResponse>;
}
