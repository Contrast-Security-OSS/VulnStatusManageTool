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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.viewers.ArrayContentProvider;
import org.eclipse.jface.viewers.CheckStateChangedEvent;
import org.eclipse.jface.viewers.CheckboxTableViewer;
import org.eclipse.jface.viewers.ColumnLabelProvider;
import org.eclipse.jface.viewers.ICheckStateListener;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;

import com.contrastsecurity.vulnstatusmanagetool.model.Filter;

public class AttackEventFilterDialog extends Dialog {

    private Map<FilterEnum, Set<Filter>> filterMap;
    private CheckboxTableViewer ruleNameViewer;
    private CheckboxTableViewer severityViewer;
    private CheckboxTableViewer appViewer;
    private CheckboxTableViewer currentStatusViewer;
    private CheckboxTableViewer pendingStatusViewer;
    private CheckboxTableViewer orgViewer;
    private PropertyChangeSupport support = new PropertyChangeSupport(this);

    public AttackEventFilterDialog(Shell parentShell, Map<FilterEnum, Set<Filter>> filterMap) {
        super(parentShell);
        this.filterMap = filterMap;
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite composite = (Composite) super.createDialogArea(parent);
        GridLayout compositeLt = new GridLayout(3, false);
        compositeLt.marginWidth = 25;
        compositeLt.marginHeight = 5;
        compositeLt.horizontalSpacing = 5;
        composite.setLayout(compositeLt);
        GridData compositeGrDt = new GridData(GridData.FILL_BOTH);
        composite.setLayoutData(compositeGrDt);

        // #################### ルール名 #################### //
        Group ruleNameGrp = new Group(composite, SWT.NONE);
        GridLayout ruleNameGrpLt = new GridLayout(1, false);
        ruleNameGrpLt.marginWidth = 10;
        ruleNameGrpLt.marginHeight = 10;
        ruleNameGrp.setLayout(ruleNameGrpLt);
        GridData ruleNameGrpGrDt = new GridData(GridData.FILL_BOTH);
        ruleNameGrpGrDt.minimumWidth = 200;
        ruleNameGrp.setLayoutData(ruleNameGrpGrDt);
        ruleNameGrp.setText("ルール名");

        final Table ruleNameTable = new Table(ruleNameGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData ruleNameTableGrDt = new GridData(GridData.FILL_BOTH);
        ruleNameTable.setLayoutData(ruleNameTableGrDt);
        ruleNameViewer = new CheckboxTableViewer(ruleNameTable);
        ruleNameViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> ruleNameLabelList = new ArrayList<String>();
        List<String> ruleNameValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.RULE_NAME)) {
            ruleNameLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                ruleNameValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (ruleNameValidLabelList.isEmpty()) {
            ruleNameValidLabelList.addAll(ruleNameLabelList);
        }
        ruleNameViewer.setContentProvider(new ArrayContentProvider());
        ruleNameViewer.setInput(ruleNameLabelList);
        ruleNameViewer.setCheckedElements(ruleNameValidLabelList.toArray());
        ruleNameViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button ruleNameBulkBtn = new Button(ruleNameGrp, SWT.CHECK);
        ruleNameBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        ruleNameBulkBtn.setText("すべて");
        ruleNameBulkBtn.setSelection(true);
        ruleNameBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (ruleNameBulkBtn.getSelection()) {
                    ruleNameValidLabelList.addAll(ruleNameLabelList);
                    ruleNameViewer.setCheckedElements(ruleNameValidLabelList.toArray());
                    ruleNameViewer.refresh();
                } else {
                    ruleNameViewer.setCheckedElements(new ArrayList<String>().toArray());
                    ruleNameViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        // #################### 重大度 #################### //
        Group severityGrp = new Group(composite, SWT.NONE);
        GridLayout severityGrpLt = new GridLayout(1, false);
        severityGrpLt.marginWidth = 10;
        severityGrpLt.marginHeight = 10;
        severityGrp.setLayout(severityGrpLt);
        GridData severityGrpGrDt = new GridData(GridData.FILL_BOTH);
        severityGrpGrDt.minimumWidth = 200;
        severityGrp.setLayoutData(severityGrpGrDt);
        severityGrp.setText("重大度");

        final Table severityTable = new Table(severityGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData severityTableGrDt = new GridData(GridData.FILL_BOTH);
        severityTable.setLayoutData(severityTableGrDt);
        severityViewer = new CheckboxTableViewer(severityTable);
        severityViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> severityLabelList = new ArrayList<String>();
        List<String> severityValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.SEVERITY)) {
            severityLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                severityValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (severityValidLabelList.isEmpty()) {
            severityValidLabelList.addAll(severityLabelList);
        }
        severityViewer.setContentProvider(new ArrayContentProvider());
        severityViewer.setInput(severityLabelList);
        severityViewer.setCheckedElements(severityValidLabelList.toArray());
        severityViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button severityBulkBtn = new Button(severityGrp, SWT.CHECK);
        severityBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        severityBulkBtn.setText("すべて");
        severityBulkBtn.setSelection(true);
        severityBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (severityBulkBtn.getSelection()) {
                    severityValidLabelList.addAll(severityLabelList);
                    severityViewer.setCheckedElements(severityValidLabelList.toArray());
                    severityViewer.refresh();
                } else {
                    severityViewer.setCheckedElements(new ArrayList<String>().toArray());
                    severityViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        // #################### アプリケーション #################### //
        Group appGrp = new Group(composite, SWT.NONE);
        GridLayout appGrpLt = new GridLayout(1, false);
        appGrpLt.marginWidth = 10;
        appGrpLt.marginHeight = 10;
        appGrp.setLayout(appGrpLt);
        GridData appGrpGrDt = new GridData(GridData.FILL_BOTH);
        appGrpGrDt.minimumWidth = 200;
        appGrp.setLayoutData(appGrpGrDt);
        appGrp.setText("アプリケーション");

        final Table appTable = new Table(appGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData appTableGrDt = new GridData(GridData.FILL_BOTH);
        appTable.setLayoutData(appTableGrDt);
        appViewer = new CheckboxTableViewer(appTable);
        appViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> appLabelList = new ArrayList<String>();
        List<String> appValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.APP_NAME)) {
            appLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                appValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (appValidLabelList.isEmpty()) {
            appValidLabelList.addAll(appLabelList);
        }
        appViewer.setContentProvider(new ArrayContentProvider());
        appViewer.setInput(appLabelList);
        appViewer.setCheckedElements(appValidLabelList.toArray());
        appViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button appBulkBtn = new Button(appGrp, SWT.CHECK);
        appBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        appBulkBtn.setText("すべて");
        appBulkBtn.setSelection(true);
        appBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (appBulkBtn.getSelection()) {
                    appValidLabelList.addAll(appLabelList);
                    appViewer.setCheckedElements(appValidLabelList.toArray());
                    appViewer.refresh();
                } else {
                    appViewer.setCheckedElements(new ArrayList<String>().toArray());
                    appViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        // #################### 現在ステータス #################### //
        Group currentStatusGrp = new Group(composite, SWT.NONE);
        GridLayout currentStatusGrpLt = new GridLayout(1, false);
        currentStatusGrpLt.marginWidth = 10;
        currentStatusGrpLt.marginHeight = 10;
        currentStatusGrp.setLayout(currentStatusGrpLt);
        GridData currentStatusGrpGrDt = new GridData(GridData.FILL_BOTH);
        currentStatusGrpGrDt.minimumWidth = 200;
        currentStatusGrp.setLayoutData(currentStatusGrpGrDt);
        currentStatusGrp.setText("ステータス");

        final Table currentStatusTable = new Table(currentStatusGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData currentStatusTableGrDt = new GridData(GridData.FILL_BOTH);
        currentStatusTable.setLayoutData(currentStatusTableGrDt);
        currentStatusViewer = new CheckboxTableViewer(currentStatusTable);
        currentStatusViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> currentStatusLabelList = new ArrayList<String>();
        List<String> currentStatusValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.STATUS)) {
            currentStatusLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                currentStatusValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (currentStatusValidLabelList.isEmpty()) {
            currentStatusValidLabelList.addAll(currentStatusLabelList);
        }
        currentStatusViewer.setContentProvider(new ArrayContentProvider());
        currentStatusViewer.setInput(currentStatusLabelList);
        currentStatusViewer.setCheckedElements(currentStatusValidLabelList.toArray());
        currentStatusViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button currentStatusBulkBtn = new Button(currentStatusGrp, SWT.CHECK);
        currentStatusBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        currentStatusBulkBtn.setText("すべて");
        currentStatusBulkBtn.setSelection(true);
        currentStatusBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (currentStatusBulkBtn.getSelection()) {
                    currentStatusValidLabelList.addAll(currentStatusLabelList);
                    currentStatusViewer.setCheckedElements(currentStatusValidLabelList.toArray());
                    currentStatusViewer.refresh();
                } else {
                    currentStatusViewer.setCheckedElements(new ArrayList<String>().toArray());
                    currentStatusViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        // #################### 保留中ステータス #################### //
        Group pendingStatusGrp = new Group(composite, SWT.NONE);
        GridLayout pendingStatusGrpLt = new GridLayout(1, false);
        pendingStatusGrpLt.marginWidth = 10;
        pendingStatusGrpLt.marginHeight = 10;
        pendingStatusGrp.setLayout(pendingStatusGrpLt);
        GridData pendingStatusGrpGrDt = new GridData(GridData.FILL_BOTH);
        pendingStatusGrpGrDt.minimumWidth = 200;
        pendingStatusGrp.setLayoutData(pendingStatusGrpGrDt);
        pendingStatusGrp.setText("保留中ステータス");

        final Table pendingStatusTable = new Table(pendingStatusGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData pendingStatusTableGrDt = new GridData(GridData.FILL_BOTH);
        pendingStatusTable.setLayoutData(pendingStatusTableGrDt);
        pendingStatusViewer = new CheckboxTableViewer(pendingStatusTable);
        pendingStatusViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> pendingStatusLabelList = new ArrayList<String>();
        List<String> pendingStatusValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.PENDING_STATUS)) {
            pendingStatusLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                pendingStatusValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (pendingStatusValidLabelList.isEmpty()) {
            pendingStatusValidLabelList.addAll(pendingStatusLabelList);
        }
        pendingStatusViewer.setContentProvider(new ArrayContentProvider());
        pendingStatusViewer.setInput(pendingStatusLabelList);
        pendingStatusViewer.setCheckedElements(pendingStatusValidLabelList.toArray());
        pendingStatusViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button pendingStatusBulkBtn = new Button(pendingStatusGrp, SWT.CHECK);
        pendingStatusBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        pendingStatusBulkBtn.setText("すべて");
        pendingStatusBulkBtn.setSelection(true);
        pendingStatusBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (pendingStatusBulkBtn.getSelection()) {
                    pendingStatusValidLabelList.addAll(pendingStatusLabelList);
                    pendingStatusViewer.setCheckedElements(pendingStatusValidLabelList.toArray());
                    pendingStatusViewer.refresh();
                } else {
                    pendingStatusViewer.setCheckedElements(new ArrayList<String>().toArray());
                    pendingStatusViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        // #################### 組織 #################### //
        Group orgGrp = new Group(composite, SWT.NONE);
        GridLayout orgGrpLt = new GridLayout(1, false);
        orgGrpLt.marginWidth = 10;
        orgGrpLt.marginHeight = 10;
        orgGrp.setLayout(orgGrpLt);
        GridData orgGrpGrDt = new GridData(GridData.FILL_BOTH);
        orgGrpGrDt.minimumWidth = 200;
        orgGrp.setLayoutData(orgGrpGrDt);
        orgGrp.setText("組織");

        final Table orgTable = new Table(orgGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
        GridData orgTableGrDt = new GridData(GridData.FILL_BOTH);
        orgTable.setLayoutData(orgTableGrDt);
        orgViewer = new CheckboxTableViewer(orgTable);
        orgViewer.setLabelProvider(new ColumnLabelProvider() {
            @Override
            public String getText(Object element) {
                return element.toString();
            }
        });
        List<String> orgLabelList = new ArrayList<String>();
        List<String> orgValidLabelList = new ArrayList<String>();
        for (Filter filter : filterMap.get(FilterEnum.ORG_NAME)) {
            orgLabelList.add(filter.getLabel());
            if (filter.isValid()) {
                orgValidLabelList.add(filter.getLabel());
            } else {
            }
        }
        if (orgValidLabelList.isEmpty()) {
            orgValidLabelList.addAll(orgLabelList);
        }
        orgViewer.setContentProvider(new ArrayContentProvider());
        orgViewer.setInput(orgLabelList);
        orgViewer.setCheckedElements(orgValidLabelList.toArray());
        orgViewer.addCheckStateListener(new ICheckStateListener() {
            @Override
            public void checkStateChanged(CheckStateChangedEvent event) {
                checkStateUpdate();
            }
        });

        final Button orgBulkBtn = new Button(orgGrp, SWT.CHECK);
        orgBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        orgBulkBtn.setText("すべて");
        orgBulkBtn.setSelection(true);
        orgBulkBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (orgBulkBtn.getSelection()) {
                    orgValidLabelList.addAll(orgLabelList);
                    orgViewer.setCheckedElements(orgValidLabelList.toArray());
                    orgViewer.refresh();
                } else {
                    orgViewer.setCheckedElements(new ArrayList<String>().toArray());
                    orgViewer.refresh();
                }
                checkStateUpdate();
            }
        });

        return composite;
    }

    private void checkStateUpdate() {
        // ルール名
        Object[] ruleNameItems = ruleNameViewer.getCheckedElements();
        List<String> strItems = new ArrayList<String>();
        for (Object item : ruleNameItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.RULE_NAME)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }
        // 重大度
        Object[] severityItems = severityViewer.getCheckedElements();
        strItems.clear();
        for (Object item : severityItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.SEVERITY)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }
        // アプリケーション
        Object[] appItems = appViewer.getCheckedElements();
        strItems.clear();
        for (Object item : appItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.APP_NAME)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }
        // ステータス
        Object[] currentStatusItems = currentStatusViewer.getCheckedElements();
        strItems.clear();
        for (Object item : currentStatusItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.STATUS)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }
        // 保留中ステータス
        Object[] pendingStatusItems = pendingStatusViewer.getCheckedElements();
        strItems.clear();
        for (Object item : pendingStatusItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.PENDING_STATUS)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }
        // 組織
        Object[] orgItems = orgViewer.getCheckedElements();
        strItems.clear();
        for (Object item : orgItems) {
            strItems.add((String) item);
        }
        for (Filter filter : filterMap.get(FilterEnum.ORG_NAME)) {
            if (strItems.contains(filter.getLabel())) {
                filter.setValid(true);
            } else {
                filter.setValid(false);
            }
        }

        support.firePropertyChange("auditFilter", null, filterMap); //$NON-NLS-1$
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, IDialogConstants.CANCEL_ID, "閉じる", true);
    }

    @Override
    protected void okPressed() {
        super.okPressed();
    }

    @Override
    protected void setShellStyle(int newShellStyle) {
        super.setShellStyle(SWT.CLOSE | SWT.TITLE | SWT.RESIZE | SWT.APPLICATION_MODAL);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText("保留中の脆弱性フィルタ");
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        this.support.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        this.support.removePropertyChangeListener(listener);
    }
}
