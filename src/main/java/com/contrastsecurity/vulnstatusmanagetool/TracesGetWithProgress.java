/*
 * MIT License
 * Copyright (c) 2025 Contrast Security Japan G.K.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

package com.contrastsecurity.vulnstatusmanagetool;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.vulnstatusmanagetool.api.Api;
import com.contrastsecurity.vulnstatusmanagetool.api.TraceApi;
import com.contrastsecurity.vulnstatusmanagetool.api.TracesApi;
import com.contrastsecurity.vulnstatusmanagetool.model.Filter;
import com.contrastsecurity.vulnstatusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.vulnstatusmanagetool.model.Organization;
import com.contrastsecurity.vulnstatusmanagetool.model.Trace;

public class TracesGetWithProgress implements IRunnableWithProgress {

    private Shell shell;
    private PreferenceStore ps;
    private List<Organization> orgs;
    private VulnTypeEnum vulnType;
    private DetectTypeEnum detectType;
    private Date frDetectedDate;
    private Date toDetectedDate;
    private List<ItemForVulnerability> allVulns;
    private Set<Filter> ruleNameFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> severityFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> applicationFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> organizationFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> statusFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> pendingStatusFilterSet = new LinkedHashSet<Filter>();

    Logger logger = LogManager.getLogger("csvdltool"); //$NON-NLS-1$

    public TracesGetWithProgress(Shell shell, PreferenceStore ps, List<Organization> orgs, VulnTypeEnum vulnType, DetectTypeEnum detectType, Date frDate, Date toDate) {
        this.shell = shell;
        this.ps = ps;
        this.orgs = orgs;
        this.vulnType = vulnType;
        this.detectType = detectType;
        this.frDetectedDate = frDate;
        this.toDetectedDate = toDate;
        this.allVulns = new ArrayList<ItemForVulnerability>();
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException {
        SubMonitor subMonitor = SubMonitor.convert(monitor).setWorkRemaining(100 * this.orgs.size());
        monitor.setTaskName("脆弱性一覧の読み込み...");
        for (Organization org : this.orgs) {
            try {
                monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...", org.getName())); //$NON-NLS-1$
                monitor.subTask("脆弱性一覧を読み込んでいます...");
                List<ItemForVulnerability> allTraces = new ArrayList<ItemForVulnerability>();
                Api tracesApi = new TracesApi(this.shell, this.ps, org, this.vulnType, this.detectType, frDetectedDate, toDetectedDate, 0);
                List<ItemForVulnerability> tmpTraces = (List<ItemForVulnerability>) tracesApi.post();
                int totalTracesCount = tracesApi.getTotalCount();
                int traceProcessCount = 0;
                monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                SubMonitor child1Monitor = subMonitor.split(100).setWorkRemaining(totalTracesCount);
                for (ItemForVulnerability vul : tmpTraces) {
                    if (monitor.isCanceled()) {
                        throw new OperationCanceledException();
                    }
                    Thread.sleep(50);
                    Api traceApi = new TraceApi(this.shell, this.ps, org, vul.getVulnerability().getApplication().getId(), vul.getVulnerability().getUuid());
                    Trace trace = (Trace) traceApi.get();
                    vul.getVulnerability().setNotes(trace.getNotes());
                    vul.getVulnerability().setOrg(org);
                    child1Monitor.worked(1);
                    traceProcessCount++;
                    monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                    monitor.subTask(trace.getTitle());
                }
                allTraces.addAll(tmpTraces);
                boolean traceIncompleteFlg = false;
                traceIncompleteFlg = totalTracesCount > allTraces.size();
                while (traceIncompleteFlg) {
                    Thread.sleep(100);
                    tracesApi = new TracesApi(this.shell, this.ps, org, this.vulnType, this.detectType, frDetectedDate, toDetectedDate, allTraces.size());
                    tmpTraces = (List<ItemForVulnerability>) tracesApi.post();
                    for (ItemForVulnerability vul : tmpTraces) {
                        if (monitor.isCanceled()) {
                            throw new OperationCanceledException();
                        }
                        Thread.sleep(50);
                        Api traceApi = new TraceApi(this.shell, this.ps, org, vul.getVulnerability().getApplication().getId(), vul.getVulnerability().getUuid());
                        Trace trace = (Trace) traceApi.get();
                        vul.getVulnerability().setNotes(trace.getNotes());
                        vul.getVulnerability().setOrg(org);
                        child1Monitor.worked(1);
                        traceProcessCount++;
                        monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                        monitor.subTask(trace.getTitle());
                    }
                    allTraces.addAll(tmpTraces);
                    traceIncompleteFlg = totalTracesCount > allTraces.size();
                }
                this.allVulns.addAll(allTraces);
                child1Monitor.done();
                Thread.sleep(100);
            } catch (OperationCanceledException oce) {
                throw new InvocationTargetException(new OperationCanceledException("キャンセルされました。"));
            } catch (Exception e) {
                throw new InvocationTargetException(e);
            }
        }
        subMonitor.done();
    }

    public List<ItemForVulnerability> getAllVulns() {
        return this.allVulns;
    }

    public Map<FilterEnum, Set<Filter>> getFilterMap() {
        for (ItemForVulnerability vuln : this.allVulns) {
            ruleNameFilterSet.add(new Filter(vuln.getVulnerability().getRuleName()));
            severityFilterSet.add(new Filter(SeverityEnum.valueOf(vuln.getVulnerability().getSeverity()).getLabel(), vuln.getVulnerability().getSeverity()));
            applicationFilterSet.add(new Filter(vuln.getVulnerability().getApplication().getName()));
            organizationFilterSet.add(new Filter(vuln.getVulnerability().getOrg().getName()));
            Optional<StatusEnum> status = StatusEnum.fromValue(vuln.getVulnerability().getStatus());
            status.ifPresentOrElse(s -> statusFilterSet.add(new Filter(s.getLabel(), vuln.getVulnerability().getStatus())),
                    () -> statusFilterSet.add(new Filter(vuln.getVulnerability().getStatus())));
            if (vuln.getVulnerability().getPendingStatus() != null) {
                Optional<StatusEnum> pendingStatus = StatusEnum.fromValue(vuln.getVulnerability().getPendingStatus().getStatus());
                pendingStatus.ifPresentOrElse(s -> pendingStatusFilterSet.add(new Filter(s.getLabel(), vuln.getVulnerability().getStatus())),
                        () -> pendingStatusFilterSet.add(new Filter(vuln.getVulnerability().getStatus())));
            }
        }
        Map<FilterEnum, Set<Filter>> filterMap = new HashMap<FilterEnum, Set<Filter>>();
        filterMap.put(FilterEnum.RULE_NAME, ruleNameFilterSet);
        filterMap.put(FilterEnum.SEVERITY, severityFilterSet);
        filterMap.put(FilterEnum.APP_NAME, applicationFilterSet);
        filterMap.put(FilterEnum.ORG_NAME, organizationFilterSet);
        filterMap.put(FilterEnum.STATUS, statusFilterSet);
        filterMap.put(FilterEnum.PENDING_STATUS, pendingStatusFilterSet);
        return filterMap;
    }

}
