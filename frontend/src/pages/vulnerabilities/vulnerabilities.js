import { Dialog, Notify } from 'quasar';

import BasicEditor from 'components/editor/Editor.vue';
import Breadcrumb from 'components/breadcrumb'
import Cvss3Calculator from 'components/cvss3calculator'
import Cvss4Calculator from 'components/cvss4calculator'
import TextareaArray from 'components/textarea-array'
import CustomFields from 'components/custom-fields'

import VulnerabilityService from '@/services/vulnerability'
import DataService from '@/services/data'
import { useUserStore } from 'src/stores/user'
import Utils from '@/services/utils'

import { $t } from 'boot/i18n'

const userStore = useUserStore()

export default {
    data: () => {
        return {
            userStore: userStore,
            // Vulnerabilities list
            vulnerabilities: [],
            // Loading state
            loading: true,
            // Datatable headers
            dtHeaders: [
                {name: 'title', label: $t('title'), field: 'title', align: 'left', sortable: true},
                {name: 'category', label: $t('category'), field: 'category', align: 'left', sortable: true},
                {name: 'type', label: $t('type'), field: 'type', align: 'left', sortable: true},
                {name: 'action', label: '', field: 'action', align: 'left', sortable: false},
            ],
            // Datatable pagination
            pagination: {
                page: 1,
                rowsPerPage: 25,
                sortBy: 'title'
            },
            rowsPerPageOptions: [
                {label:'25', value:25},
                {label:'50', value:50},
                {label:'100', value:100},
                {label:'All', value:0}
            ],
            filteredRowsCount: 0,
            // Vulnerabilities languages
            languages: [],
            locale: '',
            // Search filter
            search: {title: '', type: '', category: '', valid: 0, new: 1, updates: 2},
            // Errors messages
            errors: {title: ''},
            // Selected or New Vulnerability
            currentVulnerability: {
                cvss: '',
                cvss4: '',
                priority: '',
                remediationComplexity: '',
                details: [] 
            },
            currentLanguage: "",
            displayFilters: {valid: true, new: true, updates: true},
            dtLanguage: "",
            currentDetailsIndex: 0,
            vulnerabilityId: '',
            vulnUpdates: [],
            currentUpdate: '',
            currentUpdateLocale: '',
            vulnTypes: [],
            // Merge vulnerabilities
            mergeTitle: 'Merged Findings',
            mergeLocale: '',
            mergeSelectedVulns: [],
            merging: false,
            // Vulnerability categories
            vulnCategories: [],
            currentCategory: null,
            // Custom Fields
            customFields: [],
            // Nessus import
            nessusImporting: false,
            // Bulk approve
            selectedVulnerabilities: []
        }
    },

    components: {
        BasicEditor,
        Breadcrumb,
        Cvss3Calculator,
        Cvss4Calculator,
        TextareaArray,
        CustomFields
    },

    mounted: function() {
        this.getLanguages()
        this.getVulnTypes()
        this.getVulnerabilities()
        this.getVulnerabilityCategories()
        this.getCustomFields()
    },

    watch: {
        currentLanguage: function(val, oldVal) {
            this.setCurrentDetails();
        }
    },

    computed: {
        vulnTypesLang: function() {
            return this.vulnTypes.filter(type => type.locale === this.currentLanguage);
        },

        computedVulnerabilities: function() {
            var result = [];
            this.vulnerabilities.forEach(vuln => {
                for (var i=0; i<vuln.details.length; i++) {
                    if (vuln.details[i].locale === this.dtLanguage && vuln.details[i].title) {
                        result.push(vuln);
                    }
                }
            })
            return result;
        },

        vulnCategoriesOptions: function() {
            var result = this.vulnCategories.map(cat => {return cat.name})
            result.unshift('No Category')
            return result
        },

        vulnTypeOptions: function() {
            var result = this.vulnTypes.filter(type => type.locale === this.dtLanguage).map(type => {return type.name})
            result.unshift('Undefined')
            return result
        }
    },

    methods: {
        // Get available languages
        getLanguages: function() {
            DataService.getLanguages()
            .then((data) => {
                this.languages = data.data.datas;
                if (this.languages.length > 0) {
                    this.dtLanguage = this.languages[0].locale;
                    this.mergeLocale = this.languages[0].locale;
                    this.cleanCurrentVulnerability();
                }
            })
            .catch((err) => {
                console.log(err)
            })
        },

         // Get available custom fields
         getCustomFields: function() {
            DataService.getCustomFields()
            .then((data) => {
                this.customFields = data.data.datas
            })
            .catch((err) => {
                console.log(err)
            })
        },

        // Get Vulnerabilities types
        getVulnTypes: function() {
            DataService.getVulnerabilityTypes()
            .then((data) => {
                this.vulnTypes = data.data.datas;
            })
            .catch((err) => {
                console.log(err)
            })
        },

        // Get available vulnerability categories
        getVulnerabilityCategories: function() {
            DataService.getVulnerabilityCategories()
            .then((data) => {
                this.vulnCategories = data.data.datas;
            })
            .catch((err) => {
                console.log(err)
            })
        },

        getVulnerabilities: function() {
            this.loading = true
            VulnerabilityService.getVulnerabilities()
            .then((data) => {
                this.vulnerabilities = data.data.datas
                this.loading = false
            })
            .catch((err) => {
                console.log(err)
                Notify.create({
                    message: err.response.data.datas,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            })
        },

        createVulnerability: function() {
            this.cleanErrors();
            var index = this.currentVulnerability.details.findIndex(obj => obj.title !== '');
            if (index < 0)
                this.errors.title = $t('err.titleRequired');
            
            if (this.errors.title)
                return;

            VulnerabilityService.createVulnerabilities([this.currentVulnerability])
            .then(() => {
                this.getVulnerabilities();
                this.$refs.createModal.hide();
                Notify.create({
                    message: $t('msg.vulnerabilityCreatedOk'),
                    color: 'positive',
                    textColor:'white',
                    position: 'top-right'
                })
            })
            .catch((err) => {
                Notify.create({
                    message: err.response.data.datas,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            })
        },

        updateVulnerability: function() {
            this.cleanErrors();
            var index = this.currentVulnerability.details.findIndex(obj => obj.title !== '');
            if (index < 0)
                this.errors.title = $t('err.titleRequired');
            
            if (this.errors.title)
                return;

            VulnerabilityService.updateVulnerability(this.vulnerabilityId, this.currentVulnerability)
            .then(() => {
                this.getVulnerabilities();
                this.$refs.editModal.hide();
                this.$refs.updatesModal.hide();
                Notify.create({
                    message: $t('msg.vulnerabilityUpdatedOk'),
                    color: 'positive',
                    textColor:'white',
                    position: 'top-right'
                })
            })
            .catch((err) => {
                Notify.create({
                    message: err.response.data.datas,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            })
        },

        deleteVulnerability: function(vulnerabilityId) {
            VulnerabilityService.deleteVulnerability(vulnerabilityId)
            .then(() => {
                this.getVulnerabilities();
                Notify.create({
                    message: $t('msg.vulnerabilityDeletedOk'),
                    color: 'positive',
                    textColor:'white',
                    position: 'top-right'
                })
            })
            .catch((err) => {
                Notify.create({
                    message: err.response.data.datas,
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            })
        },

        confirmDeleteVulnerability: function(row) {
            Dialog.create({
                title: $t('msg.confirmSuppression'),
                message: $t('msg.vulnerabilityWillBeDeleted'),
                ok: {label: $t('btn.confirm'), color: 'negative'},
                cancel: {label: $t('btn.cancel'), color: 'white'}
            })
            .onOk(() => this.deleteVulnerability(row._id))
        },

        getVulnUpdates: function(vulnId) {
            VulnerabilityService.getVulnUpdates(vulnId)
            .then((data) => {
                this.vulnUpdates = data.data.datas;
                this.vulnUpdates.forEach(vuln => {
                    vuln.customFields = Utils.filterCustomFields('vulnerability', this.currentVulnerability.category, this.customFields, vuln.customFields, vuln.locale)
                })
                if (this.vulnUpdates.length > 0) {
                    this.currentUpdate = this.vulnUpdates[0]._id || null;
                    this.currentLanguage = this.vulnUpdates[0].locale || null;
                }
            })
            .catch((err) => {
                console.log(err)
            })
        },

        clone: function(row) {
            this.cleanCurrentVulnerability();
            
            this.currentVulnerability = this.$_.cloneDeep(row)
            this.setCurrentDetails();
            
            this.vulnerabilityId = row._id;
            if (userStore.isAllowed('vulnerabilities:update'))
                this.getVulnUpdates(this.vulnerabilityId);
        },

        editChangeCategory: function(category) {
            Dialog.create({
                title: $t('msg.confirmCategoryChange'),
                message: $t('msg.categoryChangingNotice'),
                ok: {label: $t('btn.confirm'), color: 'negative'},
                cancel: {label: $t('btn.cancel'), color: 'white'}
            })
            .onOk(() => {
                if (category){
                    this.currentVulnerability.category = category.name
                }
                else {
                    this.currentVulnerability.category = null
                }
                this.setCurrentDetails()
            })
        },

        cleanErrors: function() {
            this.errors.title = '';
        },  

        cleanCurrentVulnerability: function() {
            this.cleanErrors();
            this.currentVulnerability.cvss = '';
            this.currentVulnerability.cvss4 = '';
            this.currentVulnerability.priority = '';
            this.currentVulnerability.remediationComplexity = '';
            this.currentVulnerability.details = [];
            this.currentLanguage = this.dtLanguage;
            if (this.currentCategory && this.currentCategory.name) 
                this.currentVulnerability.category = this.currentCategory.name
            else
                this.currentVulnerability.category = null

            this.setCurrentDetails();
        },

        // Create detail if locale doesn't exist else set the currentDetailIndex
        setCurrentDetails: function(value) {
            var index = this.currentVulnerability.details.findIndex(obj => obj.locale === this.currentLanguage);
            if (index < 0) {
                var details = {
                    locale: this.currentLanguage,
                    title: '',
                    vulnType: '',
                    description: '',
                    observation: '',
                    remediation: '',
                    references: [],
                    customFields: []
                }
                details.customFields = Utils.filterCustomFields('vulnerability', this.currentVulnerability.category, this.customFields, [], this.currentLanguage)
                
                this.currentVulnerability.details.push(details)
                index = this.currentVulnerability.details.length - 1;
            }
            else {
                this.currentVulnerability.details[index].customFields = Utils.filterCustomFields('vulnerability', this.currentVulnerability.category, this.customFields, this.currentVulnerability.details[index].customFields, this.currentLanguage)
            }
            this.currentDetailsIndex = index;
        },

        isTextInCustomFields: function(field) {

            if (this.currentVulnerability.details[this.currentDetailsIndex].customFields) {
                return typeof this.currentVulnerability.details[this.currentDetailsIndex].customFields.find(f => {
                    return f.customField === field.customField._id && f.text === field.text
                }) === 'undefined'
            }
            return false
        },

        getTextDiffInCustomFields: function(field) {
            var result = ''
            if (this.currentVulnerability.details[this.currentDetailsIndex].customFields) {
                this.currentVulnerability.details[this.currentDetailsIndex].customFields.find(f => {
                    if (f.customField === field.customField._id)
                        result = f.text
                })
            }
            return result
        },

        getDtTitle: function(row) {
            var index = row.details.findIndex(obj => obj.locale === this.dtLanguage);
            if (index < 0 || !row.details[index].title)
                return $t('err.notDefinedLanguage');
            else
                return row.details[index].title;         
        },

        getDtType: function(row) {
            var index = row.details.findIndex(obj => obj.locale === this.dtLanguage);
            if (index < 0 || !row.details[index].vulnType)
                return "Undefined";
            else
                return row.details[index].vulnType;         
        },

        customSort: function(rows, sortBy, descending) {
            if (rows) {
                var data = [...rows];

                if (sortBy === 'type') {
                    (descending)
                        ? data.sort((a, b) => this.getDtType(b).localeCompare(this.getDtType(a)))
                        : data.sort((a, b) => this.getDtType(a).localeCompare(this.getDtType(b)))
                }
                else if (sortBy === 'title') {
                    (descending)
                        ? data.sort((a, b) => this.getDtTitle(b).localeCompare(this.getDtTitle(a)))
                        : data.sort((a, b) => this.getDtTitle(a).localeCompare(this.getDtTitle(b)))
                }
                else if (sortBy === 'category') {
                    (descending)
                        ? data.sort((a, b) => (b.category || $t('noCategory')).localeCompare(a.category || $t('noCategory')))
                        : data.sort((a, b) => (a.category || $t('noCategory')).localeCompare(b.category || $t('noCategory')))
                }
                return data;
            }
        },

        customFilter: function(rows, terms, cols, getCellValue) {
            var result = rows && rows.filter(row => {
                var title = this.getDtTitle(row).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                var type = this.getDtType(row).toLowerCase()
                var category = (row.category || $t('noCategory')).toLowerCase()
                var termTitle = (terms.title || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                var termCategory = (terms.category || "").toLowerCase()
                var termVulnType = (terms.type || "").toLowerCase()
                return title.indexOf(termTitle) > -1 && 
                type.indexOf(termVulnType||"") > -1 &&
                category.indexOf(termCategory||"") > -1 &&
                (row.status === terms.valid || row.status === terms.new || row.status === terms.updates)
            })
            this.filteredRowsCount = result.length;
            return result;
        },

        goToAudits: function(row) {
            var title = this.getDtTitle(row);
            this.$router.push({name: 'audits', query: {findingTitle: title}});
        },

        getVulnTitleLocale: function(vuln, locale) {
            for (var i=0; i<vuln.details.length; i++) {
                if (vuln.details[i].locale === locale && vuln.details[i].title) return vuln.details[i].title;
            }
            return "undefined";
        },

        // Reset merge modal state
        resetMergeModal: function() {
            this.mergeTitle = 'Merged Findings';
            this.mergeSelectedVulns = [];
            this.merging = false;
            if (this.languages.length > 0) {
                this.mergeLocale = this.languages[0].locale;
            }
        },

        // Get priority color for badge
        getPriorityColor: function(priority) {
            switch(priority) {
                case 4: return 'negative';  // Urgent
                case 3: return 'orange';    // High
                case 2: return 'warning';   // Medium
                case 1: return 'positive';  // Low
                default: return 'grey';
            }
        },

        // Get priority label
        getPriorityLabel: function(priority) {
            switch(priority) {
                case 4: return $t('urgent');
                case 3: return $t('high');
                case 2: return $t('medium');
                case 1: return $t('low');
                default: return '';
            }
        },

        // Merge selected vulnerabilities
        mergeVulnerabilities: function() {
            if (this.mergeSelectedVulns.length < 2) {
                Notify.create({
                    message: $t('msg.selectAtLeast2Vulnerabilities'),
                    color: 'warning',
                    textColor: 'white',
                    position: 'top-right'
                });
                return;
            }

            const title = this.mergeTitle || 'Merged Findings';
            const locale = this.mergeLocale || (this.languages.length > 0 ? this.languages[0].locale : 'en');

            Dialog.create({
                title: $t('msg.confirmMerge'),
                message: $t('msg.mergeVulnerabilitiesConfirm', [this.mergeSelectedVulns.length]),
                html: true,
                ok: {label: $t('btn.confirm'), color: 'secondary'},
                cancel: {label: $t('btn.cancel'), color: 'white'}
            })
            .onOk(() => {
                this.merging = true;
                VulnerabilityService.mergeVulnerabilities(this.mergeSelectedVulns, title, locale)
                .then((data) => {
                    this.merging = false;
                    this.$refs.mergeModal.hide();
                    this.getVulnerabilities();
                    Notify.create({
                        message: $t('msg.vulnerabilityMergeOk', [data.data.datas.merged]),
                        color: 'positive',
                        textColor: 'white',
                        position: 'top-right'
                    });
                })
                .catch((err) => {
                    this.merging = false;
                    Notify.create({
                        message: err.response?.data?.datas || $t('msg.mergeError'),
                        color: 'negative',
                        textColor: 'white',
                        position: 'top-right'
                    });
                });
            });
        },

        dblClick: function(row) {
            this.clone(row)
            if (userStore.isAllowed('vulnerabilities:update') && row.status === 2)
                this.$refs.updatesModal.show()
            else
                this.$refs.editModal.show()
        },

        // Import vulnerabilities from Nessus XML file
        importNessus: function(files) {
            if (!files || files.length === 0) return
            
            const file = files[0]
            const ext = file.name.split('.').pop().toLowerCase()
            
            if (ext !== 'nessus' && ext !== 'xml') {
                Notify.create({
                    message: $t('msg.invalidNessusFile'),
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
                return
            }

            this.nessusImporting = true
            
            VulnerabilityService.importNessus(file, this.dtLanguage)
            .then((data) => {
                this.nessusImporting = false
                const result = data.data.datas
                var message = ""
                var color = "positive"
                
                if (result.created === 0 && result.duplicates === 0) {
                    message = $t('msg.nessusImportEmpty')
                    color = "warning"
                } else if (result.duplicates === 0) {
                    message = $t('msg.nessusImportOk', [result.created])
                } else if (result.created === 0) {
                    message = $t('msg.nessusImportAllExists', [result.duplicates.length || result.duplicates])
                    color = "warning"
                } else {
                    message = $t('msg.nessusImportPartial', [result.created, result.duplicates.length || result.duplicates])
                    color = "orange"
                }
                
                if (result.summary) {
                    message += `<br><br><strong>Summary:</strong><br>`
                    message += `Critical: ${result.summary.byPriority.urgent}, High: ${result.summary.byPriority.high}, `
                    message += `Medium: ${result.summary.byPriority.medium}, Low: ${result.summary.byPriority.low}`
                }
                
                Notify.create({
                    message: message,
                    html: true,
                    closeBtn: 'x',
                    color: color,
                    textColor: 'white',
                    position: 'top-right',
                    timeout: 10000
                })
                
                this.getVulnerabilities()
                
                // Reset file input
                if (this.$refs.importNessus) {
                    this.$refs.importNessus.value = ''
                }
            })
            .catch((err) => {
                this.nessusImporting = false
                Notify.create({
                    message: err.response?.data?.datas || $t('msg.nessusImportError'),
                    color: 'negative',
                    textColor: 'white',
                    position: 'top-right'
                })
            })
        },

        // Bulk approve selected vulnerabilities
        bulkApprove: function() {
            if (this.selectedVulnerabilities.length === 0) return

            const ids = this.selectedVulnerabilities.map(v => v._id)
            
            Dialog.create({
                title: $t('msg.bulkApproveConfirm'),
                message: $t('msg.bulkApproveNotice', [ids.length]),
                html: true,
                ok: {label: $t('btn.confirm'), color: 'positive'},
                cancel: {label: $t('btn.cancel'), color: 'white'}
            })
            .onOk(() => {
                VulnerabilityService.bulkApprove(ids)
                .then((data) => {
                    const result = data.data.datas
                    Notify.create({
                        message: $t('msg.bulkApproveOk', [result.approved]),
                        html: true,
                        color: 'positive',
                        textColor: 'white',
                        position: 'top-right'
                    })
                    this.selectedVulnerabilities = []
                    this.getVulnerabilities()
                })
                .catch((err) => {
                    Notify.create({
                        message: err.response?.data?.datas || 'Error approving vulnerabilities',
                        color: 'negative',
                        textColor: 'white',
                        position: 'top-right'
                    })
                })
            })
        }
    }
}