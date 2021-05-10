import {getObject} from "../../utils";

class Decoders {

    constructor() {
        this.titleSelector = '[class="euiTitle euiTitle--medium"]';
        this.decodersButtonSelector = '[class="euiSideNavItem euiSideNavItem--trunk"]';
        this.tableSelector = '[class="euiTableRow customRowClass euiTableRow-isClickable"]';
        this.dropdownPaginationSelector = '[data-test-subj="tablePaginationPopoverButton"]';
        this.listPages = 'nav[class="euiPagination"]';
        this.customDecodersButtonSelector = '[class="euiButtonGroup euiButtonGroup--m"]';
        this.manageDecodersFilesButtonSelector = ':nth-child(3) > .euiButtonEmpty > .euiButtonContent';
        this.editDecoderButtonSelector = '.euiTableCellContent > div > :nth-child(1) > .euiButtonIcon';
        this.saveDecoderButtonSelector = '.euiFlexItem--flexGrowZero > .euiButton > .euiButtonContent';
        this.messageConfirmSaveSelector = '.euiText > span';
        this.buttonRestartSelector = '.euiText--small > .euiFlexGroup > .euiFlexItem--flexGrowZero > .euiButton > .euiButtonContent';
    }

    getDecodersButton() {
        return getObject(this.decodersButtonSelector)
            .eq(1);
    }

    getTittle() {
        return getObject(this.titleSelector);
    }

    getTable() {
        return getObject(this.tableSelector);
    }

    getTablePaginationDropdowns() {
        return getObject(this.dropdownPaginationSelector);
    }

    getTablePaginationListPages() {
        return getObject(this.listPages);
    }

    getCustomDecodersButton() {
        return getObject(this.customDecodersButtonSelector);
    }

    getManageDecodersFilesButton() {
        return getObject(this.manageDecodersFilesButtonSelector);
    }

    getEditDecoderButton() {
        return getObject(this.editDecoderButtonSelector);
    }

    getSaveDecoderButton() {
        return getObject(this.saveDecoderButtonSelector);
    }

    getMessageConfirmSave() {
        return getObject(this.messageConfirmSaveSelector);
    }

    getButtonRestart() {
        return getObject(this.buttonRestartSelector);
    }

}

export default Decoders;
