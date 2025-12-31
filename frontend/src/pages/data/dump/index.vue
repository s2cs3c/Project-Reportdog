<template>
    <div class="row">
        <div class="col-md-10 col-12 offset-md-1 q-mt-md">
            <q-card>
                <q-card-section class="q-py-xs bg-blue-grey-5 text-white">
                    <div class="text-h6">{{$t('nav.vulnerabilities')}}</div>
                </q-card-section>
                <q-separator />
                <div v-if="userStore.isAllowed('vulnerabilities:create')">
                    <q-card-section>
                        <div class="text-bold">{{$t('importVulnerabilities')}}</div>
                    </q-card-section>
                    <q-card-section>
                        <div class="text-grey-8" v-html="$t('importVulnerabilitiesInfo')"></div>
                    </q-card-section>
                    <q-card-section>
                        <input
                        ref="importVulnerabilities"
                        value=""
                        type="file"
                        multiple
                        accept=".yml, .json"
                        class="hidden"
                        @change="importVulnerabilities($event.target.files)"
                        />
                        <q-btn 
                        :label="$t('import')"
                        color="secondary"
                        flat
                        class="bg-secondary text-white"
                        @click="$refs.importVulnerabilities.click()"
                        />
                    </q-card-section>
                    <q-separator />
                </div>
                <div v-if="userStore.isAllowed('vulnerabilities:create')">
                    <q-card-section>
                        <div class="text-bold">{{$t('importNessus')}}</div>
                    </q-card-section>
                    <q-card-section>
                        <div class="text-grey-8" v-html="$t('importNessusInfo')"></div>
                    </q-card-section>
                    <q-card-section class="row q-gutter-md items-center">
                        <q-select
                        v-model="nessusLocale"
                        :options="languages"
                        option-value="locale"
                        option-label="language"
                        emit-value
                        map-options
                        :label="$t('language')"
                        outlined
                        dense
                        style="min-width: 150px"
                        />
                        <input
                        ref="importNessus"
                        value=""
                        type="file"
                        accept=".nessus, .xml"
                        class="hidden"
                        @change="importNessus($event.target.files)"
                        />
                        <q-btn 
                        :label="$t('importNessus')"
                        flat
                        :loading="nessusImporting"
                        style="background-color: #26a69a; color: #fff;"
                        @click="$refs.importNessus.click()"
                        >
                            <template v-slot:loading>
                                <q-spinner-gears class="on-left" />
                                {{$t('importing')}}...
                            </template>
                        </q-btn>
                    </q-card-section>
                    <q-separator />
                </div>
                <q-card-section>
                    <div class="text-bold">{{$t('exportVulnerabilities')}}</div>
                </q-card-section>
                <q-card-section>
                        <div class="text-grey-8" v-html="$t('exportVulnerabilitiesInfo')"></div>
                    </q-card-section>
                    <q-card-section>
                        <q-btn 
                        :label="$t('export')"
                        color="secondary"
                        flat
                        class="bg-secondary text-white"
                        @click="getVulnerabilities"
                        />
                    </q-card-section>
                    <q-separator />
                    <div v-if="userStore.isAllowed('vulnerabilities:delete-all')">
                        <q-card-section>
                            <div class="text-bold">{{$t('deleteAllVulnerabilities')}}</div>
                        </q-card-section>
                        <q-card-section>
                            <div class="text-grey-8" v-html="$t('deleteAllVulnerabilitiesInfo')"></div>
                        </q-card-section>
                        <q-card-section>
                            <q-btn 
                            :label="$t('btn.deleteAll')"
                            flat
                            class="bg-negative text-white"
                            @click="deleteAllVulnerabilities"
                            />
                        </q-card-section>
                    </div>
            </q-card>
        </div>

        <div class="col-md-10 col-12 offset-md-1 q-mt-md">
            <q-card>
                <q-card-section class="q-py-xs bg-blue-grey-5 text-white">
                    <div class="text-h6">{{$t('nav.audits')}}</div>
                </q-card-section>
                <q-separator />
                <q-card-section>
                    TODO
                </q-card-section>
            </q-card>
        </div>
    </div>
</template>

<script src='./dump.js'></script>

<style></style>