import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './categories.models';
export declare class CategoriesDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Categories
     * -------------
     *
     * List Categories.
     */
    bulkReadCategories(): DataState<X.BulkReadCategoriesResponseEntity[]>;
    bulkReadCategories2(): Observable<X.BulkReadCategoriesResponseEntity[]>;
}
