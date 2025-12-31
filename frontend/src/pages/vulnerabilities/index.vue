<template>
    <div class="row">
        <div v-if="languages.length === 0" class="col-md-4 offset-md-4 q-mt-md">
            <p>{{$t('noLanguage')}} <a href="/data/custom">{{$t('nav.data')}} -> {{$t('customData')}} -> {{$t('languages')}}</a></p>
        </div>
        <div v-else class="col-xl-8 col-12 offset-xl-2 q-pa-md">
            <q-table
                class="sticky-header-table"
                :columns="dtHeaders"
                :rows="computedVulnerabilities"
                :filter="search"
                :filter-method="customFilter"
                v-model:pagination="pagination"
                v-model:selected="selectedVulnerabilities"
                :sort-method="customSort"
                separator="none"
                row-key="_id"
                :loading="loading"
                :selection="userStore.isAllowed('vulnerabilities:update') ? 'multiple' : 'none'"
                @row-dblclick="dblClick"
            >
                <template v-slot:top>
                    <q-select 
                    class="col-md-2"
                    v-model="dtLanguage" 
                    :label="$t('language')" 
                    :options="languages" 
                    option-value="locale"
                    option-label="language" 
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                    <q-toggle :label="$t('btn.valid')" v-model="search.valid" :true-value=0 />
                    <q-toggle :label="$t('btn.new')" color="light-blue" v-model="search.new" :true-value=1 />
                    <q-toggle :label="$t('btn.updates')" color="orange" v-model="search.updates" :true-value=2 />
                    <q-btn 
                    v-if="userStore.isAllowed('vulnerabilities:update')"
                    class="q-ml-md"
                    :label="$t('mergeVulnerabilities')"
                    outline
                    color="secondary" 
                    no-caps
                    @click="$refs.mergeModal.show()"
                    />
                    <q-btn 
                    v-if="userStore.isAllowed('vulnerabilities:update') && selectedVulnerabilities.length > 0"
                    class="q-ml-md"
                    :label="$t('bulkApproveSelected') + ' (' + selectedVulnerabilities.length + ')'"
                    unelevated
                    color="positive" 
                    no-caps
                    @click="bulkApprove()"
                    />
                    <q-space />
                    <input
                    ref="importNessus"
                    value=""
                    type="file"
                    accept=".nessus, .xml"
                    class="hidden"
                    @change="importNessus($event.target.files)"
                    />
                    <q-btn 
                    v-if="userStore.isAllowed('vulnerabilities:create')"
                    class="q-mr-md"
                    :label="$t('importNessus')"
                    unelevated
                    no-caps
                    :loading="nessusImporting"
                    style="background-color: #26a69a; color: #fff;"
                    @click="$refs.importNessus.click()"
                    >
                        <template v-slot:loading>
                            <q-spinner-gears class="on-left" />
                            {{$t('importing')}}...
                        </template>
                    </q-btn>
                    <q-btn-dropdown 
                    v-if="userStore.isAllowed('vulnerabilities:create')"
                    unelevated
                    color="secondary"
                    no-caps
                    :label="$t('newVulnerability')"
                    >
                        <q-list separator>
                            <q-item-label header>{{$t('selectCategory')}}</q-item-label>
                            <q-item clickable v-close-popup @click="currentCategory = null; cleanCurrentVulnerability(); $refs.createModal.show()">
                                <q-item-section>
                                <q-item-label>{{$t('noCategory')}}</q-item-label>
                                </q-item-section>
                            </q-item>
                            <q-item v-for="category of vulnCategories" :key="category.name" clickable v-close-popup @click="currentCategory = $_.cloneDeep(category); cleanCurrentVulnerability(); $refs.createModal.show()">
                                <q-item-section>
                                <q-item-label>{{category.name}}</q-item-label>
                                </q-item-section>
                            </q-item>
                        </q-list>
                    </q-btn-dropdown>            
                </template>

                <template v-slot:top-row="props">
                    <q-tr>
                        <q-td v-if="userStore.isAllowed('vulnerabilities:update')" auto-width></q-td>
                        <q-td style="width: 60%">
                            <q-input 
                            dense
                            :label="$t('search')"
                            v-model="search.title"
                            clearable
                            autofocus
                            outlined
                            />
                        </q-td>
                        <q-td style="width: 20%">
                            <q-select 
                            dense
                            :label="$t('search')"
                            v-model="search.category"
                            clearable
                            :options="vulnCategoriesOptions"
                            options-sanitize
                            outlined
                            />
                        </q-td>
                        <q-td style="width: 20%">
                            <q-select 
                            dense
                            :label="$t('search')"
                            v-model="search.type"
                            clearable
                            :options="vulnTypeOptions"
                            options-sanitize
                            outlined
                            />
                        </q-td>
                        <q-td></q-td>
                    </q-tr>
                </template>

                <template v-slot:body="props">
                    <q-tr @dblclick="dblClick(props.row)" v-if="getDtTitle(props.row) !== 'Not defined for this language yet'" :props="props" :class="(props.row.status === 1)?'bg-light-blue-2':(props.row.status === 2)?'bg-orange-2':''">
                        <q-td auto-width v-if="userStore.isAllowed('vulnerabilities:update')">
                            <q-checkbox v-model="props.selected" />
                        </q-td>
                        <q-td key="title" :props="props">
                            {{getDtTitle(props.row)}}
                        </q-td>
                        <q-td key="category" :props="props">
                            {{props.row.category || $t('noCategory')}}
                        </q-td>
                        <q-td key="type" :props="props">
                            {{getDtType(props.row)}}
                        </q-td>
                        <q-td key="action" :props="props" style="width:1px">
                            <q-btn v-if="userStore.isAllowed('vulnerabilities:update')" size="sm" flat color="primary" icon="fa fa-edit" @click="clone(props.row); (props.row.status === 2)?$refs.updatesModal.show():$refs.editModal.show()">
                                <q-tooltip anchor="bottom middle" self="center left" :delay="500" class="text-bold">{{$t('tooltip.edit')}}</q-tooltip>                                                    
                            </q-btn>
                            <q-btn v-else size="sm" flat color="primary" icon="fa fa-eye" @click="clone(props.row); $refs.editModal.show()">
                                <q-tooltip anchor="bottom middle" self="center left" :delay="500" class="text-bold">{{$t('tooltip.view')}}</q-tooltip>                            
                            </q-btn>
                            <q-btn size="sm" flat color="secondary" icon="fa fa-fingerprint" @click="goToAudits(props.row)">
                                <q-tooltip anchor="bottom middle" self="center left" :delay="500" class="text-bold">{{$t('tooltip.findAudits')}}</q-tooltip>                            
                            </q-btn>
                            <q-btn v-if="userStore.isAllowed('vulnerabilities:delete')" size="sm" flat color="negative" icon="fa fa-trash" @click="confirmDeleteVulnerability(props.row)">
                                <q-tooltip anchor="bottom middle" self="center left" :delay="500" class="text-bold">{{$t('tooltip.delete')}}</q-tooltip>                            
                            </q-btn>
                        </q-td>
                    </q-tr>
                </template>          
                
                <template v-slot:bottom="scope">
                    <span v-if="computedVulnerabilities.length === 1">{{filteredRowsCount}} / 1 {{$t('vulnerabilityNum1')}} ({{$t('total')}}: {{vulnerabilities.length}})</span>                
                    <span v-else>{{filteredRowsCount}} / {{computedVulnerabilities.length}} {{$t('vulnerabilitiesNums')}} ({{$t('total')}}: {{vulnerabilities.length}})</span>    
                    <q-space />
                    <span>{{$t('resultsPerPage')}}</span>
                    <q-select
                    class="q-px-md"
                    v-model="pagination.rowsPerPage"
                    :options="rowsPerPageOptions"
                    emit-value
                    map-options
                    dense
                    options-dense
                    options-cover
                    borderless
                    />
                    <q-pagination input v-model="pagination.page" :max="scope.pagesNumber" />            
                </template> 
        
            </q-table>
        </div>
    </div>

    <q-dialog v-if="languages.length > 0" ref="createModal" maximized position="right" persistent @hide="cleanCurrentVulnerability()">
        <q-card :style="($q.screen.gt.lg)?'width: 50vw':'width:1000px'">
            <q-bar class="bg-fixed-primary text-white">
                <div class="q-toolbar-title">
                    <span v-if="currentCategory">{{$t('addVulnerability')}} ({{currentCategory.name}})</span>
                    <span v-else>{{$t('addVulnerability')}} ({{$t('noCategory')}})</span>
                </div>
                <q-space />
                <q-btn dense flat icon="close" @click="$refs.createModal.hide()" />
            </q-bar>

            <q-card-section>
                <div class="q-col-gutter-md row">
                    <q-input
                    :label="$t('title')+' *'"
                    stack-label
                    class="col-md-8"
                    autofocus
                    :error="!!errors.title"
                    :error-message="errors.title"
                    hide-bottom-space
                    @keyup.enter="createVulnerability()"
                    v-model="currentVulnerability.details[currentDetailsIndex].title"
                    outlined
                    />
                    <q-select 
                    class="col-md-2"
                    :label="$t('type')"
                    v-model="currentVulnerability.details[currentDetailsIndex].vulnType" 
                    :options="vulnTypesLang" 
                    option-value="name" 
                    option-label="name" 
                    emit-value 
                    map-options
                    options-sanitize
                    outlined
                    />
                    <q-select
                    :label="$t('language')"
                    stack-label
                    class="col-md-2"
                    v-model="currentLanguage"
                    :options="languages"
                    option-value="locale"
                    option-label="language"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('description')" stack-label>
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].description" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('observation')" stack-label>
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].observation" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section v-if="$settings.report.public.scoringMethods.CVSS3">
                <div class="col-md-12">
                    <cvss3-calculator
                    v-model="currentVulnerability.cvssv3"
                    @cvssScoreChange="currentVulnerability.cvssScore = $event"
                    />
                </div>
            </q-card-section>
            <q-card-section v-if="$settings.report.public.scoringMethods.CVSS4">
                <div class="col-md-12">
                    <cvss4-calculator
                    v-model="currentVulnerability.cvssv4"
                    @cvssScoreChange="currentVulnerability.cvssScore = $event"
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('remediation')" stack-label>
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].remediation" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section>
                <div class="q-col-gutter-md row">
                    <q-select
                    :label="$t('remediationComplexity')"
                    stack-label
                    class="col-md-6"
                    v-model="currentVulnerability.remediationComplexity"
                    :options="[{label: $t('easy'), value: 1},{label: $t('medium'), value: 2},{label: $t('complex'), value: 3}]"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                    <q-select
                    :label="$t('remediationPriority')"
                    stack-label
                    class="col-md-6"
                    v-model="currentVulnerability.priority"
                    :options="[{label: $t('low'), value: 1},{label: $t('medium'), value: 2},{label: $t('high'), value: 3},{label: $t('urgent'), value: 4}]"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <textarea-array :label="$t('references')" v-model="currentVulnerability.details[currentDetailsIndex].references" />
            </q-card-section>

            <q-expansion-item 
            :label="$t('customFields')"
            default-opened
            header-class="bg-blue-grey-5 text-white" 
            expand-icon-class="text-white"
            >
                <custom-fields 
                ref="customfields" 
                v-model="currentVulnerability.details[currentDetailsIndex].customFields" 
                :category="currentVulnerability.category" 
                custom-element="QCardSection"
                display="vuln"
                :locale="currentLanguage"
                />
            </q-expansion-item>

            <q-separator />

            <q-card-actions align="right">
                <q-btn color="primary" outline @click="$refs.createModal.hide()">{{$t('btn.cancel')}}</q-btn>
                <q-btn color="secondary" unelevated @click="createVulnerability()">{{$t('btn.create')}}</q-btn>
            </q-card-actions>
        </q-card>
    </q-dialog>

    <q-dialog v-if="languages.length > 0" ref="editModal" maximized position="right" :persistent="userStore.isAllowed('vulnerabilities:update')" @hide="cleanCurrentVulnerability()">
        <q-card :style="($q.screen.gt.lg)?'width: 50vw':'width:1000px'">
            <q-bar class="bg-fixed-primary text-white">
                <div class="q-toolbar-title">
                    <span v-if="currentVulnerability.category">{{$t('editVulnerability')}} ({{currentVulnerability.category}})</span>
                    <span v-else>{{$t('editVulnerability')}} ({{$t('noCategory')}})</span>
                </div>
                <q-separator vertical color="white" class="q-mx-md" />
                <q-btn-dropdown
                :label="$t('changeCategory')"
                color="white"
                >
                <q-list separator>
                    <q-item-label header>{{$t('selectCategory')}}</q-item-label>
                    <q-item clickable v-close-popup @click="editChangeCategory()">
                        <q-item-section>
                        <q-item-label>{{$t('noCategory')}}</q-item-label>
                        </q-item-section>
                    </q-item>
                    <q-item v-for="category of vulnCategories" :key="category.name" clickable v-close-popup @click="editChangeCategory(category)">
                        <q-item-section>
                        <q-item-label>{{category.name}}</q-item-label>
                        </q-item-section>
                    </q-item>
                </q-list>
                </q-btn-dropdown>
                <q-separator v-if="currentVulnerability.creator" vertical color="white" class="q-ml-md q-mr-sm" />
                <div v-if="currentVulnerability.creator" class="q-toolbar-title" style="height:80%">
                    <span>
                        <q-badge color="grey" style="height:100%">
                            Creator: {{currentVulnerability.creator.username}}
                        </q-badge>
                    </span>
                </div>
                <q-space />
                <q-btn dense flat icon="close" @click="$refs.editModal.hide()" />
            </q-bar>

            <q-card-section>
                <div class="q-col-gutter-md row">
                    <q-input
                    :label="$t('title')+' *'"
                    stack-label
                    class="col-md-8"
                    autofocus
                    :error="!!errors.title"
                    :error-message="errors.title"
                    hide-bottom-space
                    @keyup.enter="updateVulnerability()"
                    v-model="currentVulnerability.details[currentDetailsIndex].title"
                    outlined
                    />
                    <q-select 
                    class="col-md-2"
                    :label="$t('type')"
                    v-model="currentVulnerability.details[currentDetailsIndex].vulnType" 
                    :options="vulnTypesLang" 
                    option-value="name" 
                    option-label="name" 
                    emit-value 
                    map-options
                    options-sanitize
                    outlined
                    />
                    <q-select
                    :label="$t('language')"
                    stack-label
                    class="col-md-2"
                    v-model="currentLanguage"
                    :options="languages"
                    option-value="locale"
                    option-label="language"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('description')" stack-label class="basic-editor">
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].description" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('observation')" stack-label class="basic-editor">
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].observation" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section v-if="$settings.report.public.scoringMethods.CVSS3">
                <div class="col-md-12">
                    <cvss3-calculator
                    v-model="currentVulnerability.cvssv3"
                    @cvssScoreChange="currentVulnerability.cvssScore = $event"
                    />
                </div>
            </q-card-section>
            <q-card-section v-if="$settings.report.public.scoringMethods.CVSS4">
                <div class="col-md-12">
                    <cvss4-calculator
                    v-model="currentVulnerability.cvssv4"
                    @cvssScoreChange="currentVulnerability.cvssScore = $event"
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <q-field borderless :label="$t('remediation')" stack-label class="basic-editor">
                    <template v-slot="control">
                        <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].remediation" />
                    </template>
                </q-field>
            </q-card-section>
            <q-card-section>
                <div class="q-col-gutter-md row">
                    <q-select
                    :label="$t('remediationComplexity')"
                    stack-label
                    class="col-md-6"
                    v-model="currentVulnerability.remediationComplexity"
                    :options="[{label: $t('easy'), value: 1},{label: $t('medium'), value: 2},{label: $t('complex'), value: 3}]"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                    <q-select
                    :label="$t('remediationPriority')"
                    stack-label
                    class="col-md-6"
                    v-model="currentVulnerability.priority"
                    :options="[{label: $t('low'), value: 1},{label: $t('medium'), value: 2},{label: $t('high'), value: 3},{label: $t('urgent'), value: 4}]"
                    map-options
                    emit-value
                    options-sanitize
                    outlined
                    />
                </div>
            </q-card-section>
            <q-card-section>
                <textarea-array :label="$t('references')" v-model="currentVulnerability.details[currentDetailsIndex].references" />
            </q-card-section>

            <q-expansion-item 
            :label="$t('customFields')"
            default-opened
            header-class="bg-blue-grey-5 text-white" 
            expand-icon-class="text-white">
                <custom-fields 
                ref="customfields" 
                v-model="currentVulnerability.details[currentDetailsIndex].customFields" 
                custom-element="QCardSection"
                :locale="currentLanguage"
                />
            </q-expansion-item>

            <q-separator />

            <q-card-actions align="right" v-if="userStore.isAllowed('vulnerabilities:update')">
                <q-btn color="primary" outline @click="$refs.editModal.hide()">{{$t('btn.cancel')}}</q-btn>
                <q-btn v-if="currentVulnerability.status === 1" label="Approve" color="light-blue" unelevated @click="updateVulnerability()" />
                <q-btn v-else color="secondary" unelevated @click="updateVulnerability()">{{$t('btn.update')}}</q-btn>
            </q-card-actions>
        </q-card>
    </q-dialog>

    <q-dialog v-if="languages.length > 0" ref="updatesModal" full-width full-height persistent @hide="cleanCurrentVulnerability()">
        <q-layout view="lHh lpr lFf" container>
            <q-header elevated>    
                    <q-bar class="bg-fixed-primary text-white">
                    <div class="q-toolbar-title">
                        {{$t('updateVulnerability')}}
                    </div>
                    <q-space />
                    <q-btn dense flat icon="close" @click="$refs.updatesModal.hide()" />
                </q-bar>
            </q-header>
            <q-page-container>
                <q-page class="row">
                    <q-card class="col-md-6">
                        <q-card-section>
                            <q-tabs
                            value="current"
                            dense
                            align="left"
                            no-caps
                            indicator-color="primary"
                            class="bg-blue-grey-2"
                            >
                                <q-tab name="current" :label="$t('current')" />
                            </q-tabs>
                        </q-card-section>
                        <q-card-section class="q-col-gutter-md row q-pt-none">
                            <q-input
                            :label="$t('title')+' *'"
                            stack-label
                            class="col-md-8"
                            v-model="currentVulnerability.details[currentDetailsIndex].title" 
                            readonly
                            outlined
                            />
                            <q-select 
                            class="col-md-2"
                            :label="$t('type')"
                            v-model="currentVulnerability.details[currentDetailsIndex].vulnType" 
                            :options="vulnTypesLang" 
                            option-value="name" 
                            option-label="name" 
                            emit-value 
                            map-options
                            options-sanitize
                            outlined
                            />
                            <q-select
                            :label="$t('language')"
                            stack-label
                            class="col-md-2"
                            v-model="currentLanguage"
                            :options="languages"
                            option-value="locale"
                            option-label="language"
                            map-options
                            emit-value
                            readonly
                            options-sanitize
                            outlined
                            />
                        </q-card-section>
                        <q-card-section>
                            <q-field borderless :label="$t('description')" stack-label class="basic-editor">
                                <template v-slot="control">
                                    <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].description" />
                                </template>
                            </q-field>
                        </q-card-section>
                        <q-card-section>
                            <q-field borderless :label="$t('observation')" stack-label class="basic-editor">
                                <template v-slot="control">
                                    <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].observation" />
                                </template>
                            </q-field>
                        </q-card-section>
                        <q-card-section v-if="$settings.report.public.scoringMethods.CVSS3">
                            <cvss3-calculator
                            v-model="currentVulnerability.cvssv3"
                            @cvssScoreChange="currentVulnerability.cvssScore = $event"
                            />
                        </q-card-section>
                        <q-card-section v-if="$settings.report.public.scoringMethods.CVSS4">
                            <cvss4-calculator
                            v-model="currentVulnerability.cvssv4"
                            @cvssScoreChange="currentVulnerability.cvssScore = $event"
                            />
                        </q-card-section>
                        <q-card-section>
                            <q-field borderless :label="$t('remediation')" stack-label class="basic-editor">
                                <template v-slot="control">
                                    <basic-editor noAffix v-model="currentVulnerability.details[currentDetailsIndex].remediation" />
                                </template>
                            </q-field>
                        </q-card-section>
                        <q-card-section class="q-col-gutter-md row">
                            <q-select
                            :label="$t('remediationComplexity')"
                            stack-label
                            class="col-md-6"
                            v-model="currentVulnerability.remediationComplexity"
                            :options="[{label: 'Easy', value: 1},{label: 'Medium', value: 2},{label: 'Complex', value: 3}]"
                            map-options
                            emit-value
                            options-sanitize
                            outlined
                            />
                            <q-select
                            :label="$t('remediationPriority')"
                            stack-label
                            class="col-md-6"
                            v-model="currentVulnerability.priority"
                            :options="[{label: 'Low', value: 1},{label: 'Medium', value: 2},{label: 'High', value: 3},{label: 'Urgent', value: 4}]"
                            map-options
                            emit-value
                            options-sanitize
                            outlined
                            />
                        </q-card-section>
                        <q-card-section>
                            <textarea-array :label="$t('references')" v-model="currentVulnerability.details[currentDetailsIndex].references" />
                        </q-card-section>

                        <q-expansion-item 
                        :label="$t('customFields')"
                        default-opened
                        header-class="bg-blue-grey-5 text-white" 
                        expand-icon-class="text-white">
                            <div v-if="currentVulnerability.details[currentDetailsIndex].customFields">
                                <custom-fields 
                                ref="customfields" 
                                v-model="currentVulnerability.details[currentDetailsIndex].customFields" 
                                custom-element="QCardSection"
                                :locale="currentLanguage"
                                />
                            </div>
                        </q-expansion-item>

                        <q-separator />
                
                        <q-card-actions align="right">
                            <q-btn color="primary" outline @click="$refs.updatesModal.hide()">{{$t('btn.cancel')}}</q-btn>
                            <q-btn color="orange" unelevated :label="$t('btn.update')" @click="updateVulnerability()" />
                        </q-card-actions>
                    </q-card>
                    <q-card class="col-md-6">
                        <q-card-section>
                            <q-tabs
                            v-model="currentUpdate"
                            dense
                            no-caps
                            align="left"
                            indicator-color="primary"
                            class="bg-blue-grey-2"
                            >
                                <q-tab v-for="update of vulnUpdates" :key="update._id" :name="update._id" :label="update.creator.username" @click="currentLanguage = update.locale" />
                            </q-tabs>
                        </q-card-section>
                        <q-tab-panels v-model="currentUpdate">
                            <q-tab-panel v-for="update of vulnUpdates" :key="update._id" :name="update._id" class="q-pa-none">
                                <q-card-section class="row q-col-gutter-md q-pt-none">
                                    <q-input
                                    :label="$t('title')+' *'"
                                    stack-label
                                    class="col-md-8"
                                    v-model="update.title"
                                    readonly
                                    outlined
                                    />
                                    <q-select 
                                    class="col-md-2"
                                    :bg-color="(currentVulnerability.details[currentDetailsIndex].vulnType != update.vulnType)?'diffbackground':''"
                                    :label="$t('type')"
                                    v-model="update.vulnType" 
                                    :options="vulnTypesLang" 
                                    option-value="name" 
                                    option-label="name" 
                                    emit-value 
                                    map-options
                                    readonly
                                    options-sanitize
                                    outlined
                                    />
                                    <q-select
                                    :label="$t('language')"
                                    stack-label
                                    class="col-md-2"
                                    v-model="update.locale"
                                    :options="languages"
                                    option-value="locale"
                                    option-label="language"
                                    emit-value
                                    map-options
                                    readonly
                                    options-sanitize
                                    outlined
                                    />
                                </q-card-section>
                                <q-card-section>
                                    <q-field 
                                    borderless 
                                    :label="$t('description')" 
                                    stack-label
                                    :class="
                                        (currentVulnerability.details[currentDetailsIndex].description || update.description) &&
                                        (currentVulnerability.details[currentDetailsIndex].description != update.description)
                                        ?'bg-diffbackground':''
                                    "
                                    class="basic-editor"
                                    readonly>
                                        <template v-slot="control">
                                            <basic-editor noAffix 
                                            v-model="update.description" 
                                            :diff="currentVulnerability.details[currentDetailsIndex].description || ''" 
                                            :editable=false />
                                        </template>
                                    </q-field>
                                </q-card-section>
                                <q-card-section>
                                    <q-field 
                                    borderless 
                                    :label="$t('observation')" 
                                    stack-label
                                    :class="
                                    (currentVulnerability.details[currentDetailsIndex].observation || update.observation) &&
                                    (currentVulnerability.details[currentDetailsIndex].observation != update.observation)
                                    ?'bg-diffbackground':''
                                    "
                                    class="basic-editor"
                                    readonly>
                                        <template v-slot="control">
                                            <basic-editor noAffix 
                                            v-model="update.observation"
                                            :diff="currentVulnerability.details[currentDetailsIndex].observation || ''"
                                            :editable=false />
                                        </template>
                                    </q-field>
                                </q-card-section>
                                <q-card-section v-if="$settings.report.public.scoringMethods.CVSS3">
                                    <cvss3-calculator
                                    :class="(currentVulnerability.cvssv3 !== update.cvssv3)?'bg-diffbackground':''"
                                    v-model="update.cvssv3"
                                    @cvssScoreChange="update.cvssScore = $event"
                                    readonly
                                    />
                                </q-card-section>
                                <q-card-section v-if="$settings.report.public.scoringMethods.CVSS4">
                                    <cvss4-calculator
                                    :class="(currentVulnerability.cvssv4 !== update.cvssv4)?'bg-diffbackground':''"
                                    v-model="update.cvssv4"
                                    @cvssScoreChange="update.cvssScore = $event"
                                    readonly
                                    />
                                </q-card-section>
                                <q-card-section>
                                    <q-field 
                                    borderless 
                                    :label="$t('remediation')" 
                                    stack-label
                                    :class="
                                    (currentVulnerability.details[currentDetailsIndex].remediation || update.remediation) &&
                                    (currentVulnerability.details[currentDetailsIndex].remediation != update.remediation)
                                    ?'bg-diffbackground':''
                                    "
                                    class="basic-editor"
                                    readonly>
                                        <template v-slot="control">
                                            <basic-editor noAffix 
                                            v-model="update.remediation" 
                                            :diff="currentVulnerability.details[currentDetailsIndex].remediation || ''"
                                            :editable=false />
                                        </template>
                                    </q-field>
                                </q-card-section>
                                <q-card-section class="q-col-gutter-md row">
                                    <q-select
                                    :bg-color="(currentVulnerability.remediationComplexity != update.remediationComplexity)?'diffbackground':''"
                                    :label="$t('remediationComplexity')"
                                    stack-label
                                    class="col-md-6"
                                    v-model="update.remediationComplexity"
                                    :options="[{label: 'Easy', value: 1},{label: 'Medium', value: 2},{label: 'Complex', value: 3}]"
                                    map-options
                                    emit-value
                                    readonly
                                    options-sanitize
                                    outlined
                                    />
                                    <q-select
                                    :bg-color="(currentVulnerability.priority != update.priority)?'diffbackground':''"
                                    :label="$t('remediationPriority')"
                                    stack-label
                                    class="col-md-6"
                                    v-model="update.priority"
                                    :options="[{label: 'Low', value: 1},{label: 'Medium', value: 2},{label: 'High', value: 3},{label: 'Urgent', value: 4}]"
                                    map-options
                                    emit-value
                                    readonly
                                    options-sanitize
                                    outlined
                                    />
                                </q-card-section>
                                <q-card-section>
                                    <q-input
                                    :bg-color="!($_.isEqual(currentVulnerability.details[currentDetailsIndex].references, update.references))?'diffbackground':''"
                                    :label="$t('references')"
                                    stack-label
                                    :model-value="(update.references && update.references.length > 0) ? update.references.join('\n') : ''"
                                    type="textarea"
                                    readonly
                                    />
                                </q-card-section>

                                <q-expansion-item 
                                :label="$t('customFields')"
                                default-opened
                                header-class="bg-blue-grey-5 text-white" 
                                expand-icon-class="text-white">
                                    <div v-if="update.customFields">
                                        <custom-fields 
                                        ref="customfields" 
                                        v-model="update.customFields" 
                                        custom-element="QCardSection"
                                        :diff="currentVulnerability.details[currentDetailsIndex].customFields"
                                        :locale="currentLanguage"
                                        readonly
                                        />
                                    </div>
                                </q-expansion-item>
                            </q-tab-panel>
                        </q-tab-panels>
                    </q-card>
                </q-page>
            </q-page-container>
        </q-layout>
    </q-dialog>

    <q-dialog persistent ref="mergeModal" @hide="resetMergeModal">
        <q-card style="width: 800px; max-width: 800px; height: 70vh">
            <q-bar class="bg-fixed-primary text-white">
                <span>{{$t('mergeVulnerabilities')}}</span>
                <q-space />
                <q-btn dense flat icon="close" @click="$refs.mergeModal.hide()" />
            </q-bar>

            <q-card-section>
                <div class="text-grey-8 q-mb-md" v-html="$t('mergeVulnerabilitiesInfoNew')"></div>
                <div class="row q-col-gutter-md">
                    <q-input
                    class="col-md-8"
                    v-model="mergeTitle"
                    :label="$t('mergedVulnerabilityTitle')"
                    outlined
                    dense
                    />
                    <q-select
                    class="col-md-4"
                    v-model="mergeLocale"
                    :options="languages"
                    option-value="locale"
                    option-label="language"
                    map-options
                    emit-value
                    :label="$t('language')"
                    outlined
                    dense
                    options-sanitize
                    />
                </div>
            </q-card-section>

            <q-separator />

            <q-card-section class="q-py-sm bg-blue-grey-1">
                <div class="row items-center">
                    <span class="text-bold">{{$t('selectVulnerabilitiesToMerge')}}</span>
                    <q-space />
                    <q-badge color="primary">{{mergeSelectedVulns.length}} {{$t('selected')}}</q-badge>
                </div>
            </q-card-section>

            <q-card-section class="card-section-merge-list q-pa-none">
                <q-scroll-area class="full-height">
                    <q-list separator>
                        <q-item tag="label" v-for="vuln of computedVulnerabilities" :key="vuln._id" dense clickable>
                            <q-item-section side top>
                                <q-checkbox v-model="mergeSelectedVulns" :val="vuln._id" />
                            </q-item-section>
                            <q-item-section>
                                <q-item-label>{{getDtTitle(vuln)}}</q-item-label>
                                <q-item-label caption>{{vuln.category || $t('noCategory')}}</q-item-label>
                            </q-item-section>
                            <q-item-section side v-if="vuln.priority">
                                <q-badge :color="getPriorityColor(vuln.priority)">
                                    {{getPriorityLabel(vuln.priority)}}
                                </q-badge>
                            </q-item-section>
                        </q-item>
                    </q-list>
                </q-scroll-area>
            </q-card-section>

            <q-separator />

            <q-card-actions align="right">
                <q-btn color="primary" outline @click="$refs.mergeModal.hide()">{{$t('btn.cancel')}}</q-btn>
                <q-btn 
                color="secondary" 
                unelevated 
                @click="mergeVulnerabilities" 
                :disable="mergeSelectedVulns.length < 2"
                :loading="merging"
                >
                    {{$t('merge')}} ({{mergeSelectedVulns.length}})
                </q-btn>
            </q-card-actions>
        </q-card>
    </q-dialog>
</template>

<script src='./vulnerabilities.js'></script>

<style scoped>
.card-section-merge-list { 
    height: calc(70vh - 280px);
    overflow: hidden;
}
</style>