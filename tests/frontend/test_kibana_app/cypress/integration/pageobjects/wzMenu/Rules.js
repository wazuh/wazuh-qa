import {getObject} from "../../utils";

class Rules {

    constructor() {
        this.rulesButtonSelector = '[class="euiSideNavItem euiSideNavItem--trunk"]';
        this.titleSelector = '[class="euiTitle euiTitle--medium"]';
        this.tableSelector = '[class="euiTableRow customRowClass euiTableRow-isClickable"]';
        this.dropdownPaginationSelector = '[data-test-subj="tablePaginationPopoverButton"]';
        this.listPagesSelector = 'nav[class="euiPagination"]';
        this.customRulesButtonSelector = '[class="euiButtonGroup euiButtonGroup--m"]';

    }

    getRulesButton() {
        return getObject(this.rulesButtonSelector)
            .eq(0);
    }

    getTitle() {
        return getObject(this.titleSelector);
    }

    getTable(){
        return getObject(this.tableSelector);
    }

    getDropdownPagination(){
        return getObject(this.dropdownPaginationSelector);
    }

    getListPages(){
        return getObject(this.listPagesSelector);
    }

    getCustomRulesButton() {
        return getObject(this.customRulesButtonSelector);
    }

}

export default Rules;
