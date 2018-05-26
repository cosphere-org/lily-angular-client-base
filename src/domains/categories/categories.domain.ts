/**
 * Categories Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './categories.models';

@Injectable()
export class CategoriesDomain {
    constructor(private client: ClientService) {}

    /**
     * List Categories
     * -------------
     *
     * List Categories.
     */
    public bulkReadCategories(): DataState<X.BulkReadCategoriesResponse> {
        return this.client.getDataState<X.BulkReadCategoriesResponse>('/categories/');
    }

}