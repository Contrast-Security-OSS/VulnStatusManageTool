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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

import org.apache.commons.exec.OS;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.preference.PreferenceManager;
import org.eclipse.jface.preference.PreferenceNode;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.TableEditor;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.ShellEvent;
import org.eclipse.swt.events.ShellListener;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;

import com.contrastsecurity.vulnstatusmanagetool.exception.ApiException;
import com.contrastsecurity.vulnstatusmanagetool.exception.NonApiException;
import com.contrastsecurity.vulnstatusmanagetool.json.ContrastJson;
import com.contrastsecurity.vulnstatusmanagetool.model.Filter;
import com.contrastsecurity.vulnstatusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.vulnstatusmanagetool.model.Note;
import com.contrastsecurity.vulnstatusmanagetool.model.Organization;
import com.contrastsecurity.vulnstatusmanagetool.preference.AboutPage;
import com.contrastsecurity.vulnstatusmanagetool.preference.BasePreferencePage;
import com.contrastsecurity.vulnstatusmanagetool.preference.ConnectionPreferencePage;
import com.contrastsecurity.vulnstatusmanagetool.preference.MyPreferenceDialog;
import com.contrastsecurity.vulnstatusmanagetool.preference.OtherPreferencePage;
import com.contrastsecurity.vulnstatusmanagetool.preference.PreferenceConstants;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

public class Main implements PropertyChangeListener {

    public static final String WINDOW_TITLE = "VulnStatusManageTool - %s";
    // 以下のMASTER_PASSWORDはプロキシパスワードを保存する際に暗号化で使用するパスワードです。
    // 本ツールをリリース用にコンパイルする際はchangeme!を別の文字列に置き換えてください。
    public static final String MASTER_PASSWORD = "changeme!";

    // 各出力ファイルの文字コード
    public static final String CSV_WIN_ENCODING = "Shift_JIS";
    public static final String CSV_MAC_ENCODING = "UTF-8";
    public static final String FILE_ENCODING = "UTF-8";

    public static final int MINIMUM_SIZE_WIDTH = 800;
    public static final int MINIMUM_SIZE_WIDTH_MAC = 880;
    public static final int MINIMUM_SIZE_HEIGHT = 640;

    private VulnStatusManageToolShell shell;

    private Button traceLoadBtn;

    private Button settingBtn;

    private Label statusBar;

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd(E)");

    private Map<FilterEnum, Set<Filter>> traceFilterMap;

    private boolean isBulkOn;
    private boolean isFirstDetectSortDesc;
    private boolean isLastDetectSortDesc;

    private Label traceCount;
    private Button vulnTypeAllBtn;
    private Button vulnTypeOpenBtn;
    private Button vulnTypeHighConfidenceBtn;
    private Button vulnTypePendingBtn;
    private Map<VulnTypeEnum, Button> vulnTypeBtnMap;
    private Map<DetectTypeEnum, Button> detectTypeBtnMap;
    private Button firstDetectBtn;
    private Button lastDetectBtn;
    private List<Button> traceDetectedRadios = new ArrayList<Button>();
    private Button traceTermHalf1st;
    private Button traceTermHalf2nd;
    private Button traceTerm30days;
    private Button traceTermYesterday;
    private Button traceTermToday;
    private Button traceTermLastWeek;
    private Button traceTermThisWeek;
    private Button traceTermPeriod;
    private Text traceDetectedFilterTxt;
    private Date frDetectedDate;
    private Date toDetectedDate;
    private Table traceTable;
    private List<Button> checkBoxList = new ArrayList<Button>();
    private List<Integer> selectedIdxes = new ArrayList<Integer>();
    private Table noteTable;
    private List<ItemForVulnerability> traces;
    private List<ItemForVulnerability> filteredTraces = new ArrayList<ItemForVulnerability>();
    private Map<TraceDetectedDateFilterEnum, Date> traceDetectedFilterMap;
    private Button statusChangeBtn;
    private Button approveBtn;
    private Button rejectBtn;

    private PreferenceStore ps;

    private PropertyChangeSupport support = new PropertyChangeSupport(this);

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    /**
     * @param args
     */
    public static void main(String[] args) {
        Main main = new Main();
        main.initialize();
        main.createPart();
    }

    private void initialize() {
        try {
            String homeDir = System.getProperty("user.home");
            this.ps = new PreferenceStore(homeDir + "\\vulnstatusmanagetool.properties");
            if (OS.isFamilyMac()) {
                this.ps = new PreferenceStore(homeDir + "/vulnstatusmanagetool.properties");
            }
            try {
                this.ps.load();
            } catch (FileNotFoundException fnfe) {
                this.ps = new PreferenceStore("vulnstatusmanagetool.properties");
                this.ps.load();
            }
        } catch (FileNotFoundException fnfe) {
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.ps.setDefault(PreferenceConstants.IS_SUPERADMIN, "false");
            this.ps.setDefault(PreferenceConstants.IS_CREATEGROUP, "false");
            this.ps.setDefault(PreferenceConstants.GROUP_NAME, "GgHTWED8kZdQU76c");
            this.ps.setDefault(PreferenceConstants.PROXY_AUTH, "none");
            this.ps.setDefault(PreferenceConstants.CONNECTION_TIMEOUT, 3000);
            this.ps.setDefault(PreferenceConstants.SOCKET_TIMEOUT, 3000);

            this.ps.setDefault(PreferenceConstants.VULN_CHOICE, VulnTypeEnum.ALL.name());
            this.ps.setDefault(PreferenceConstants.DETECT_CHOICE, "FIRST");
            this.ps.setDefault(PreferenceConstants.TERM_START_MONTH, "Jan");
            this.ps.setDefault(PreferenceConstants.START_WEEKDAY, 1); // 月曜日
            this.ps.setDefault(PreferenceConstants.TRACE_DETECTED_DATE_FILTER, 0);

            this.ps.setDefault(PreferenceConstants.OPENED_MAIN_TAB_IDX, 0);
            this.ps.setDefault(PreferenceConstants.OPENED_SUB_TAB_IDX, 0);
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private void createPart() {
        Display display = new Display();
        shell = new VulnStatusManageToolShell(display, this);
        if (OS.isFamilyMac()) {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH_MAC, MINIMUM_SIZE_HEIGHT);
        } else {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
        }
        Image[] imageArray = new Image[5];
        imageArray[0] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon16.png"));
        imageArray[1] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon24.png"));
        imageArray[2] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon32.png"));
        imageArray[3] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon48.png"));
        imageArray[4] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon128.png"));
        shell.setImages(imageArray);
        Window.setDefaultImages(imageArray);
        setWindowTitle();
        shell.addShellListener(new ShellListener() {
            @Override
            public void shellIconified(ShellEvent event) {
            }

            @Override
            public void shellDeiconified(ShellEvent event) {
            }

            @Override
            public void shellDeactivated(ShellEvent event) {
            }

            @Override
            public void shellClosed(ShellEvent event) {
                ps.setValue(PreferenceConstants.MEM_WIDTH, shell.getSize().x);
                ps.setValue(PreferenceConstants.MEM_HEIGHT, shell.getSize().y);
                ps.setValue(PreferenceConstants.PROXY_TMP_USER, "");
                ps.setValue(PreferenceConstants.PROXY_TMP_PASS, "");
                ps.setValue(PreferenceConstants.VULN_CHOICE, getSelectedVulnType().name());
                ps.setValue(PreferenceConstants.DETECT_CHOICE, getSelectedDetectType().name());
                for (Button termBtn : traceDetectedRadios) {
                    if (termBtn.getSelection()) {
                        ps.setValue(PreferenceConstants.TRACE_DETECTED_DATE_FILTER, traceDetectedRadios.indexOf(termBtn));
                    }
                }
                if (traceTermPeriod.getSelection()) {
                    ps.setValue(PreferenceConstants.DETECT_PERIOD, String.format("%s-%s", frDetectedDate.getTime(), toDetectedDate.getTime()));
                }
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }

            @Override
            public void shellActivated(ShellEvent event) {
                boolean ngRequiredFields = false;
                String url = ps.getString(PreferenceConstants.CONTRAST_URL);
                String usr = ps.getString(PreferenceConstants.USERNAME);
                boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
                String svc = ps.getString(PreferenceConstants.SERVICE_KEY);
                if (isSuperAdmin) {
                    String api = ps.getString(PreferenceConstants.API_KEY);
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty() || api.isEmpty()) {
                        ngRequiredFields = true;
                    }
                } else {
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty()) {
                        ngRequiredFields = true;
                    }
                }
                List<Organization> orgs = getValidOrganizations();
                if (ngRequiredFields || (!isSuperAdmin && orgs.isEmpty())) {
                    traceLoadBtn.setEnabled(false);
                    settingBtn.setText("このボタンから基本設定を行ってください。");
                    uiReset();
                } else {
                    traceLoadBtn.setEnabled(true);
                    settingBtn.setText("設定");
                }
                updateTermFilterOption();
                setWindowTitle();
                if (ps.getBoolean(PreferenceConstants.PROXY_YUKO) && ps.getString(PreferenceConstants.PROXY_AUTH).equals("input")) {
                    String proxy_usr = ps.getString(PreferenceConstants.PROXY_TMP_USER);
                    String proxy_pwd = ps.getString(PreferenceConstants.PROXY_TMP_PASS);
                    if (proxy_usr == null || proxy_usr.isEmpty() || proxy_pwd == null || proxy_pwd.isEmpty()) {
                        ProxyAuthDialog proxyAuthDialog = new ProxyAuthDialog(shell);
                        int result = proxyAuthDialog.open();
                        if (IDialogConstants.CANCEL_ID == result) {
                            ps.setValue(PreferenceConstants.PROXY_AUTH, "none");
                        } else {
                            ps.setValue(PreferenceConstants.PROXY_TMP_USER, proxyAuthDialog.getUsername());
                            ps.setValue(PreferenceConstants.PROXY_TMP_PASS, proxyAuthDialog.getPassword());
                        }
                    }
                }
            }
        });

        GridLayout baseLayout = new GridLayout(1, false);
        baseLayout.marginWidth = 8;
        baseLayout.marginBottom = 0;
        baseLayout.verticalSpacing = 8;
        shell.setLayout(baseLayout);

        Group vulnListGrp = new Group(shell, SWT.NONE);
        vulnListGrp.setLayout(new GridLayout(3, false));
        GridData vulnListGrpGrDt = new GridData(GridData.FILL_BOTH);
        vulnListGrpGrDt.minimumHeight = 200;
        vulnListGrp.setLayoutData(vulnListGrpGrDt);

        Composite vulnTypeGrp = new Composite(vulnListGrp, SWT.NONE);
        vulnTypeGrp.setLayout(new GridLayout(4, false));
        GridData vulnTypeGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        vulnTypeGrp.setLayoutData(vulnTypeGrpGrDt);

        vulnTypeBtnMap = new HashMap<VulnTypeEnum, Button>();
        vulnTypeAllBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeOpenBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeHighConfidenceBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypePendingBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeBtnMap.put(VulnTypeEnum.ALL, vulnTypeAllBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.OPEN, vulnTypeOpenBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.HIGH_CONFIDENCE, vulnTypeHighConfidenceBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.PENDING_REVIEW, vulnTypePendingBtn);
        vulnTypeBtnMap.forEach((key, value) -> {
            value.setText(key.getLabel());
            value.setSelection(false);
        });

        Group detectGrp = new Group(vulnListGrp, SWT.NONE);
        detectGrp.setLayout(new GridLayout(1, false));
        GridData detectGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectGrpGrDt.horizontalSpan = 3;
        detectGrp.setLayoutData(detectGrpGrDt);
        detectGrp.setText("検出日時");
        VulnTypeEnum vulnTypeEnum = VulnTypeEnum.valueOf(this.ps.getString(PreferenceConstants.VULN_CHOICE));
        Button selectedVulnTypeBtn = vulnTypeBtnMap.get(vulnTypeEnum);
        if (selectedVulnTypeBtn != null) {
            selectedVulnTypeBtn.setSelection(true);
        } else {
            vulnTypeAllBtn.setSelection(true);
        }

        Composite detectTypeGrp = new Composite(detectGrp, SWT.NONE);
        detectTypeGrp.setLayout(new GridLayout(10, false));
        GridData detectTypeGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectTypeGrp.setLayoutData(detectTypeGrpGrDt);

        detectTypeBtnMap = new HashMap<DetectTypeEnum, Button>();
        firstDetectBtn = new Button(detectTypeGrp, SWT.RADIO);
        lastDetectBtn = new Button(detectTypeGrp, SWT.RADIO);
        detectTypeBtnMap.put(DetectTypeEnum.FIRST, firstDetectBtn);
        detectTypeBtnMap.put(DetectTypeEnum.LAST, lastDetectBtn);
        detectTypeBtnMap.forEach((key, value) -> {
            value.setText(key.getLabel());
            value.setSelection(false);
        });
        DetectTypeEnum detectTypeEnum = DetectTypeEnum.valueOf(this.ps.getString(PreferenceConstants.DETECT_CHOICE));
        Button selectedDetectTypeBtn = detectTypeBtnMap.get(detectTypeEnum);
        if (selectedDetectTypeBtn != null) {
            selectedDetectTypeBtn.setSelection(true);
        } else {
            firstDetectBtn.setSelection(true);
        }

        if (this.ps.getString(PreferenceConstants.DETECT_CHOICE).equals("FIRST")) {
            firstDetectBtn.setSelection(true);
        } else {
            lastDetectBtn.setSelection(true);
        }

        Composite detectTermGrp = new Composite(detectGrp, SWT.NONE);
        detectTermGrp.setLayout(new GridLayout(10, false));
        GridData detectTermGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectTermGrp.setLayoutData(detectTermGrpGrDt);

        new Label(detectTermGrp, SWT.LEFT).setText("取得期間：");
        // =============== 取得期間選択ラジオボタン ===============
        // 上半期
        traceTermHalf1st = new Button(detectTermGrp, SWT.RADIO);
        traceTermHalf1st.setText("上半期");
        traceDetectedRadios.add(traceTermHalf1st);
        traceTermHalf1st.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END);
                detectedDateLabelUpdate();
            }

        });
        // 下半期
        traceTermHalf2nd = new Button(detectTermGrp, SWT.RADIO);
        traceTermHalf2nd.setText("下半期");
        traceDetectedRadios.add(traceTermHalf2nd);
        traceTermHalf2nd.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END);
                detectedDateLabelUpdate();
            }

        });
        // 直近30日間
        traceTerm30days = new Button(detectTermGrp, SWT.RADIO);
        traceTerm30days.setText("直近30日間");
        traceDetectedRadios.add(traceTerm30days);
        traceTerm30days.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 昨日
        traceTermYesterday = new Button(detectTermGrp, SWT.RADIO);
        traceTermYesterday.setText("昨日");
        traceDetectedRadios.add(traceTermYesterday);
        traceTermYesterday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                detectedDateLabelUpdate();
            }
        });
        // 今日
        traceTermToday = new Button(detectTermGrp, SWT.RADIO);
        traceTermToday.setText("今日");
        traceDetectedRadios.add(traceTermToday);
        traceTermToday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 先週
        traceTermLastWeek = new Button(detectTermGrp, SWT.RADIO);
        traceTermLastWeek.setText("先週");
        traceDetectedRadios.add(traceTermLastWeek);
        traceTermLastWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 今週
        traceTermThisWeek = new Button(detectTermGrp, SWT.RADIO);
        traceTermThisWeek.setText("今週");
        traceDetectedRadios.add(traceTermThisWeek);
        traceTermThisWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 任意機関
        traceTermPeriod = new Button(detectTermGrp, SWT.RADIO);
        traceTermPeriod.setText("任意");
        traceDetectedRadios.add(traceTermPeriod);
        traceTermPeriod.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
            }
        });
        traceDetectedFilterTxt = new Text(detectTermGrp, SWT.BORDER);
        traceDetectedFilterTxt.setText("");
        traceDetectedFilterTxt.setEditable(false);
        traceDetectedFilterTxt.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        traceDetectedFilterTxt.addListener(SWT.MouseUp, new Listener() {
            public void handleEvent(Event e) {
                if (!traceTermPeriod.getSelection()) {
                    return;
                }
                FilterDetectedDateDialog filterDialog = new FilterDetectedDateDialog(shell, frDetectedDate, toDetectedDate);
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    traceLoadBtn.setFocus();
                    return;
                }
                frDetectedDate = filterDialog.getFrDate();
                toDetectedDate = filterDialog.getToDate();
                detectedDateLabelUpdate();
                if (!traceDetectedFilterTxt.getText().isEmpty()) {
                    for (Button rdo : traceDetectedRadios) {
                        rdo.setSelection(false);
                    }
                    traceTermPeriod.setSelection(true);
                }
                traceLoadBtn.setFocus();
            }
        });
        for (Button termBtn : this.traceDetectedRadios) {
            updateTermFilterOption();
            termBtn.setSelection(false);
            if (this.traceDetectedRadios.indexOf(termBtn) == this.ps.getInt(PreferenceConstants.TRACE_DETECTED_DATE_FILTER)) {
                termBtn.setSelection(true);
                Event event = new Event();
                event.widget = termBtn;
                event.type = SWT.Selection;
                termBtn.notifyListeners(SWT.Selection, event);
            }
        }
        if (traceTermPeriod.getSelection()) {
            String datePeriodStr = this.ps.getString(PreferenceConstants.DETECT_PERIOD);
            if (datePeriodStr.matches("^\\d{13}-\\d{13}$")) {
                String[] periodArray = datePeriodStr.split("-");
                if (periodArray.length > 1) {
                    long frms = Long.parseLong(periodArray[0]);
                    long toms = Long.parseLong(periodArray[1]);
                    frDetectedDate = new Date(frms);
                    toDetectedDate = new Date(toms);
                }
            }
        }
        detectedDateLabelUpdate();

        traceLoadBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData traceLoadBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceLoadBtnGrDt.horizontalSpan = 3;
        traceLoadBtnGrDt.heightHint = 30;
        traceLoadBtn.setLayoutData(traceLoadBtnGrDt);
        traceLoadBtn.setText("脆弱性一覧を取得");
        traceLoadBtn.setToolTipText("脆弱性一覧を取得します。");
        traceLoadBtn.setFont(new Font(display, "ＭＳ ゴシック", 14, SWT.BOLD));
        traceLoadBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                filteredTraces.clear();
                traceTable.clearAll();
                traceTable.removeAll();
                for (Button button : checkBoxList) {
                    button.dispose();
                }
                checkBoxList.clear();
                Date[] frToDate = getFrToDetectedDate();
                if (frToDate.length != 2) {
                    MessageDialog.openError(shell, "脆弱性一覧の取得", "取得期間を設定してください。");
                    return;
                }
                TracesGetWithProgress progress = new TracesGetWithProgress(shell, ps, getValidOrganizations(), getSelectedVulnType(), getSelectedDetectType(), frToDate[0],
                        frToDate[1]);
                ProgressMonitorDialog progDialog = new TracesGetProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    traces = progress.getAllVulns();
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    filteredTraces.addAll(traces);
                    for (ItemForVulnerability vuln : traces) {
                        addColToVulnTable(vuln, -1);
                    }
                    traceFilterMap = progress.getFilterMap();
                    traceCount.setText(String.format("%d/%d", filteredTraces.size(), traces.size())); //$NON-NLS-1$
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "脆弱性一覧の取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "脆弱性一覧の取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "脆弱性一覧の取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        SashForm sashForm = new SashForm(vulnListGrp, SWT.VERTICAL);
        GridData sashFormGrDt = new GridData(GridData.FILL_BOTH);
        sashFormGrDt.horizontalSpan = 3;
        sashForm.setLayoutData(sashFormGrDt);

        Composite topComposite = new Composite(sashForm, SWT.NONE);
        topComposite.setLayout(new GridLayout(3, false));
        GridData topCompositeGrDt = new GridData(GridData.FILL_HORIZONTAL);
        topComposite.setLayoutData(topCompositeGrDt);

        this.traceCount = new Label(topComposite, SWT.RIGHT);
        GridData traceCountGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceCountGrDt.horizontalSpan = 3;
        traceCountGrDt.minimumHeight = 12;
        traceCountGrDt.minimumWidth = 30;
        traceCountGrDt.heightHint = 12;
        traceCountGrDt.widthHint = 30;
        this.traceCount.setLayoutData(traceCountGrDt);
        this.traceCount.setFont(new Font(display, "ＭＳ ゴシック", 10, SWT.NORMAL));
        this.traceCount.setText("0/0");

        traceTable = new Table(topComposite, SWT.BORDER | SWT.FULL_SELECTION | SWT.MULTI);
        GridData traceTableGrDt = new GridData(GridData.FILL_BOTH);
        traceTableGrDt.horizontalSpan = 3;
        traceTable.setLayoutData(traceTableGrDt);
        traceTable.setLinesVisible(true);
        traceTable.setHeaderVisible(true);
        Menu menuTable = new Menu(traceTable);
        traceTable.setMenu(menuTable);
        traceTable.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                ItemForVulnerability selectedVul = filteredTraces.get(traceTable.getSelectionIndex());
                noteTable.clearAll();
                noteTable.removeAll();
                for (Note note : selectedVul.getVulnerability().getNotes()) {
                    addColToNoteTable(note, -1);
                }
            }
        });

        TableColumn column0 = new TableColumn(traceTable, SWT.NONE);
        column0.setWidth(0);
        column0.setResizable(false);
        TableColumn column1 = new TableColumn(traceTable, SWT.CENTER);
        column1.setWidth(50);
        column1.setText("有効");
        column1.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isBulkOn = !isBulkOn;
                if (selectedIdxes.isEmpty()) {
                    isBulkOn = true;
                } else {
                    if (filteredTraces.size() == selectedIdxes.size()) {
                        isBulkOn = false;
                    }
                }
                if (isBulkOn) {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(true);
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                } else {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(false);
                    }
                }
                updateBtnStatus();
            }
        });
        TableColumn column2 = new TableColumn(traceTable, SWT.CENTER);
        column2.setWidth(150);
        column2.setText("最初の検知日時");
        column2.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isFirstDetectSortDesc = !isFirstDetectSortDesc;
                traceTable.clearAll();
                traceTable.removeAll();
                if (isFirstDetectSortDesc) {
                    Collections.reverse(traces);
                    Collections.reverse(filteredTraces);
                } else {
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    Collections.sort(filteredTraces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredTraces) {
                    addColToVulnTable(vul, -1);
                }
            }
        });
        TableColumn column3 = new TableColumn(traceTable, SWT.CENTER);
        column3.setWidth(150);
        column3.setText("最後の検知日時");
        column3.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isLastDetectSortDesc = !isLastDetectSortDesc;
                traceTable.clearAll();
                traceTable.removeAll();
                if (isLastDetectSortDesc) {
                    Collections.reverse(traces);
                    Collections.reverse(filteredTraces);
                } else {
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                    Collections.sort(filteredTraces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredTraces) {
                    addColToVulnTable(vul, -1);
                }
            }
        });
        TableColumn column4 = new TableColumn(traceTable, SWT.LEFT);
        column4.setWidth(300);
        column4.setText("脆弱性");
        TableColumn column5 = new TableColumn(traceTable, SWT.CENTER);
        column5.setWidth(120);
        column5.setText("重大度");
        TableColumn column6 = new TableColumn(traceTable, SWT.CENTER);
        column6.setWidth(120);
        column6.setText("ステータス");
        TableColumn column7 = new TableColumn(traceTable, SWT.CENTER);
        column7.setWidth(120);
        column7.setText("保留中ステータス");
        TableColumn column8 = new TableColumn(traceTable, SWT.LEFT);
        column8.setWidth(300);
        column8.setText("アプリケーション");
        TableColumn column9 = new TableColumn(traceTable, SWT.LEFT);
        column9.setWidth(300);
        column9.setText("組織");

        Button traceFilterBtn = new Button(topComposite, SWT.PUSH);
        GridData traceFilterBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceFilterBtnGrDt.horizontalSpan = 3;
        traceFilterBtn.setLayoutData(traceFilterBtnGrDt);
        traceFilterBtn.setText("フィルター");
        traceFilterBtn.setToolTipText("脆弱性のフィルタリングを行います。");
        traceFilterBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (traceFilterMap == null) {
                    MessageDialog.openInformation(shell, "脆弱性フィルター", "脆弱性一覧を読み込んでください。");
                    return;
                }
                TraceFilterDialog filterDialog = new TraceFilterDialog(shell, traceFilterMap);
                filterDialog.addPropertyChangeListener(shell.getMain());
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
            }
        });

        Composite bottomComposite = new Composite(sashForm, SWT.NONE);
        bottomComposite.setLayout(new GridLayout(3, false));
        GridData bottomCompositeGrDt = new GridData(GridData.FILL_HORIZONTAL);
        bottomComposite.setLayoutData(bottomCompositeGrDt);

        sashForm.setWeights(new int[] { 75, 25 });

        noteTable = new Table(bottomComposite, SWT.BORDER | SWT.FULL_SELECTION | SWT.MULTI);
        GridData noteTableGrDt = new GridData(GridData.FILL_BOTH);
        noteTableGrDt.horizontalSpan = 3;
        // noteTableGrDt.minimumHeight = 100;
        // noteTableGrDt.heightHint = 150;
        noteTable.setLayoutData(noteTableGrDt);
        noteTable.setLinesVisible(true);
        noteTable.setHeaderVisible(true);

        TableColumn noteCol0 = new TableColumn(noteTable, SWT.NONE);
        noteCol0.setWidth(0);
        noteCol0.setResizable(false);
        TableColumn noteCol1 = new TableColumn(noteTable, SWT.CENTER);
        noteCol1.setWidth(150);
        noteCol1.setText("作成日時");
        TableColumn noteCol2 = new TableColumn(noteTable, SWT.CENTER);
        noteCol2.setWidth(200);
        noteCol2.setText("作成者");
        TableColumn noteCol3 = new TableColumn(noteTable, SWT.CENTER);
        noteCol3.setWidth(100);
        noteCol3.setText("承認処理");
        TableColumn noteCol4 = new TableColumn(noteTable, SWT.LEFT);
        noteCol4.setWidth(500);
        noteCol4.setText("コメント");
        TableColumn noteCol5 = new TableColumn(noteTable, SWT.CENTER);
        noteCol5.setWidth(100);
        noteCol5.setText("変更前ステータス");
        TableColumn noteCol6 = new TableColumn(noteTable, SWT.CENTER);
        noteCol6.setWidth(100);
        noteCol6.setText("変更後ステータス");
        TableColumn noteCol7 = new TableColumn(noteTable, SWT.CENTER);
        noteCol7.setWidth(150);
        noteCol7.setText("変更理由");

        statusChangeBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData statusChangeBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusChangeBtnGrDt.horizontalSpan = 1;
        statusChangeBtnGrDt.heightHint = 36;
        statusChangeBtn.setLayoutData(statusChangeBtnGrDt);
        statusChangeBtn.setText("ステータス変更");
        statusChangeBtn.setToolTipText("選択されている脆弱性のステータスを変更します。");
        statusChangeBtn.setFont(new Font(display, "ＭＳ ゴシック", 15, SWT.BOLD));
        statusChangeBtn.setEnabled(false);
        statusChangeBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                StatusMarkDialog statusMarkDialog = new StatusMarkDialog(shell, ps);
                int result = statusMarkDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
                StatusEnum statusEnum = statusMarkDialog.getStatus();
                SubStatusEnum subStatusEnum = statusMarkDialog.getSubStatus();
                String note = statusMarkDialog.getNote();
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                StatusMarkWithProgress progress = new StatusMarkWithProgress(shell, ps, targetMap, statusEnum, subStatusEnum, note);
                ProgressMonitorDialog progDialog = new StatusMarkProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    ContrastJson resJson = progress.getJson();
                    if (Boolean.valueOf(resJson.getSuccess())) {
                        MessageBox messageBox = new MessageBox(shell, SWT.ICON_INFORMATION | SWT.OK);
                        messageBox.setText("ステータス更新");
                        List<String> messages = resJson.getMessages();
                        messages.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messages));
                        messageBox.open();
                    } else {

                    }
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "脆弱性一覧の取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "脆弱性一覧の取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "脆弱性一覧の取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
        });

        approveBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData approveBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        approveBtnGrDt.horizontalSpan = 1;
        approveBtnGrDt.heightHint = 36;
        approveBtn.setLayoutData(approveBtnGrDt);
        approveBtn.setText("承認");
        approveBtn.setToolTipText("選択されている脆弱性のステータス変更を承認します。");
        approveBtn.setFont(new Font(display, "ＭＳ ゴシック", 15, SWT.BOLD));
        approveBtn.setEnabled(false);
        approveBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(shell, ps, targetMap, true);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    ContrastJson resJson = progress.getJson();
                    if (Boolean.valueOf(resJson.getSuccess())) {
                        MessageBox messageBox = new MessageBox(shell, SWT.ICON_INFORMATION | SWT.OK);
                        messageBox.setText("ステータス更新");
                        List<String> messages = resJson.getMessages();
                        messages.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messages));
                        messageBox.open();
                    } else {

                    }
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        rejectBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData rejectBtnGrDt = new GridData();
        rejectBtnGrDt.horizontalSpan = 1;
        rejectBtnGrDt.heightHint = 36;
        rejectBtnGrDt.widthHint = 150;
        rejectBtn.setLayoutData(rejectBtnGrDt);
        rejectBtn.setText("拒否");
        rejectBtn.setToolTipText("選択されている脆弱性のステータス変更を拒否します。");
        rejectBtn.setFont(new Font(display, "ＭＳ ゴシック", 15, SWT.NORMAL));
        rejectBtn.setEnabled(false);
        rejectBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                PendingStatusRejectDialog rejectDialog = new PendingStatusRejectDialog(shell, ps);
                int result = rejectDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
                String note = rejectDialog.getNote();
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(shell, ps, targetMap, false, note);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    ContrastJson resJson = progress.getJson();
                    if (Boolean.valueOf(resJson.getSuccess())) {
                        MessageBox messageBox = new MessageBox(shell, SWT.ICON_INFORMATION | SWT.OK);
                        messageBox.setText("ステータス更新");
                        List<String> messages = resJson.getMessages();
                        messages.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messages));
                        messageBox.open();
                    } else {

                    }
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        Composite bottomBtnGrp = new Composite(shell, SWT.NONE);
        GridLayout bottomBtnGrpLt = new GridLayout();
        bottomBtnGrpLt.numColumns = 1;
        bottomBtnGrpLt.makeColumnsEqualWidth = false;
        bottomBtnGrpLt.marginHeight = 0;
        bottomBtnGrp.setLayout(bottomBtnGrpLt);
        GridData bottomBtnGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        bottomBtnGrp.setLayoutData(bottomBtnGrpGrDt);

        // ========== 設定ボタン ==========
        settingBtn = new Button(bottomBtnGrp, SWT.PUSH);
        settingBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        settingBtn.setText("設定");
        settingBtn.setToolTipText("動作に必要な設定を行います。");
        settingBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                PreferenceManager mgr = new PreferenceManager();
                PreferenceNode baseNode = new PreferenceNode("base", new BasePreferencePage(shell));
                PreferenceNode connectionNode = new PreferenceNode("connection", new ConnectionPreferencePage());
                PreferenceNode otherNode = new PreferenceNode("other", new OtherPreferencePage());
                mgr.addToRoot(baseNode);
                mgr.addToRoot(connectionNode);
                mgr.addToRoot(otherNode);
                PreferenceNode aboutNode = new PreferenceNode("about", new AboutPage());
                mgr.addToRoot(aboutNode);
                PreferenceDialog dialog = new MyPreferenceDialog(shell, mgr);
                dialog.setPreferenceStore(ps);
                dialog.open();
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }
        });

        this.statusBar = new Label(shell, SWT.RIGHT);
        GridData statusBarGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusBarGrDt.minimumHeight = 11;
        statusBarGrDt.heightHint = 11;
        this.statusBar.setLayoutData(statusBarGrDt);
        this.statusBar.setFont(new Font(display, "ＭＳ ゴシック", 9, SWT.NORMAL));
        this.statusBar.setForeground(shell.getDisplay().getSystemColor(SWT.COLOR_DARK_GRAY));

        uiUpdate();
        int width = this.ps.getInt(PreferenceConstants.MEM_WIDTH);
        int height = this.ps.getInt(PreferenceConstants.MEM_HEIGHT);
        if (width > 0 && height > 0) {
            shell.setSize(width, height);
        } else {
            shell.setSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
            // shell.pack();
        }
        shell.open();
        try {
            while (!shell.isDisposed()) {
                if (!display.readAndDispatch()) {
                    display.sleep();
                }
            }
        } catch (Exception e) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            String trace = stringWriter.toString();
            logger.error(trace);
        }
        display.dispose();
    }

    private void detectedDateLabelUpdate() {
        if (frDetectedDate != null && toDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("%s ～ %s", sdf.format(frDetectedDate), sdf.format(toDetectedDate)));
        } else if (frDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("%s ～", sdf.format(frDetectedDate)));
        } else if (toDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("～ %s", sdf.format(toDetectedDate)));
        } else {
            traceDetectedFilterTxt.setText("");
        }
    }

    private void addColToVulnTable(ItemForVulnerability vuln, int index) {
        if (vuln == null) {
            return;
        }
        TableEditor editor = new TableEditor(traceTable);
        Button button = new Button(traceTable, SWT.CHECK);
        button.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                selectedIdxes.clear();
                for (Button button : checkBoxList) {
                    if (button.getSelection()) {
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                }
                updateBtnStatus();
            }
        });
        button.pack();
        TableItem item = new TableItem(traceTable, SWT.CENTER);
        editor.minimumWidth = button.getSize().x;
        editor.horizontalAlignment = SWT.CENTER;
        editor.setEditor(button, item, 1);
        checkBoxList.add(button);
        item.setText(2, vuln.getVulnerability().getFirstDetectedStr());
        item.setText(3, vuln.getVulnerability().getLastDetectedStr());
        item.setText(4, vuln.getVulnerability().getTitle());
        item.setText(5, SeverityEnum.valueOf(vuln.getVulnerability().getSeverity()).getLabel());
        Optional<StatusEnum> status = StatusEnum.fromValue(vuln.getVulnerability().getStatus());
        status.ifPresentOrElse(s -> item.setText(6, s.getLabel()), () -> item.setText(6, ""));
        if (vuln.getVulnerability().getPendingStatus() != null) {
            Optional<StatusEnum> pendingStatus = StatusEnum.fromValue(vuln.getVulnerability().getPendingStatus().getStatus());
            pendingStatus.ifPresentOrElse(s -> item.setText(7, s.getLabel()), () -> item.setText(7, ""));
        }
        item.setText(8, vuln.getVulnerability().getApplication().getName());
        item.setText(9, vuln.getVulnerability().getOrg().getName());
    }

    private void addColToNoteTable(Note note, int index) {
        if (note == null) {
            return;
        }
        TableItem item = new TableItem(noteTable, SWT.CENTER);
        item.setText(1, note.getCreationStr());
        item.setText(2, note.getCreator());
        String resolutionStr = note.getProperty("pending.status.resolution");
        if (!resolutionStr.isEmpty()) {
            if (Boolean.valueOf(resolutionStr)) {
                item.setText(3, "○");
            } else {
                item.setText(3, "×");
            }
        } else {
            item.setText(3, "");
        }
        item.setText(4, note.getNote());
        item.setText(5, note.getProperty("status.change.previous.status"));
        item.setText(6, note.getProperty("status.change.status"));
        item.setText(7, note.getProperty("status.change.substatus"));
    }

    private void uiReset() {
    }

    private void uiUpdate() {
    }

    public PreferenceStore getPreferenceStore() {
        return ps;
    }

    public VulnTypeEnum getSelectedVulnType() {
        for (Map.Entry<VulnTypeEnum, Button> entry : vulnTypeBtnMap.entrySet()) {
            if (entry.getValue().getSelection()) {
                return entry.getKey();
            }
        }
        return VulnTypeEnum.ALL;
    }

    public DetectTypeEnum getSelectedDetectType() {
        for (Map.Entry<DetectTypeEnum, Button> entry : detectTypeBtnMap.entrySet()) {
            if (entry.getValue().getSelection()) {
                return entry.getKey();
            }
        }
        return DetectTypeEnum.FIRST;
    }

    public List<Organization> getValidOrganizations() {
        List<Organization> orgs = new ArrayList<Organization>();
        String orgJsonStr = ps.getString(PreferenceConstants.TARGET_ORGS);
        if (orgJsonStr.trim().length() > 0) {
            try {
                List<Organization> orgList = new Gson().fromJson(orgJsonStr, new TypeToken<List<Organization>>() {
                }.getType());
                for (Organization org : orgList) {
                    if (org != null && org.isValid()) {
                        orgs.add(org);
                    }
                }
            } catch (JsonSyntaxException e) {
                return orgs;
            }
        }
        return orgs;
    }

    private void updateBtnStatus() {
        boolean existUpdatableVul = false;
        boolean existApprovalVul = false;
        for (int idx : selectedIdxes) {
            ItemForVulnerability vul = filteredTraces.get(idx);
            if (vul.getVulnerability().getPendingStatus() == null) {
                existUpdatableVul |= true;
            } else {
                existApprovalVul |= true;
            }
        }
        statusChangeBtn.setEnabled(existUpdatableVul);
        approveBtn.setEnabled(existApprovalVul);
        rejectBtn.setEnabled(existApprovalVul);
    }

    private void updateTermFilterOption() {
        this.traceDetectedFilterMap = getTraceDetectedDateMap();
        traceTermToday.setToolTipText(sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY)));
        traceTermYesterday.setToolTipText(sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY)));
        traceTerm30days.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY))));
        traceTermLastWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END))));
        traceTermThisWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END))));
        traceTermHalf1st.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END))));
        traceTermHalf2nd.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START)),
                sdf.format(traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END))));
    }

    private Date[] getFrToDetectedDate() {
        int idx = -1;
        for (Button termBtn : this.traceDetectedRadios) {
            if (termBtn.getSelection()) {
                idx = traceDetectedRadios.indexOf(termBtn);
                break;
            }
        }
        if (idx < 0) {
            idx = 0;
        }
        Date frDate = null;
        Date toDate = null;
        switch (idx) {
            case 0: // 上半期
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END);
                break;
            case 1: // 下半期
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END);
                break;
            case 2: // 30days
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                break;
            case 3: // Yesterday
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                break;
            case 4: // Today
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                break;
            case 5: // LastWeek
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END);
                break;
            case 6: // ThisWeek
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END);
                break;
            case 7: // Specify
                if (frDetectedDate == null || toDetectedDate == null) {
                    return new Date[] {};
                }
                return new Date[] { frDetectedDate, toDetectedDate };
            default:
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
        }
        return new Date[] { frDate, toDate };
    }

    public Map<TraceDetectedDateFilterEnum, Date> getTraceDetectedDateMap() {
        Map<TraceDetectedDateFilterEnum, Date> map = new HashMap<TraceDetectedDateFilterEnum, Date>();
        LocalDate today = LocalDate.now();

        map.put(TraceDetectedDateFilterEnum.TODAY, Date.from(today.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.YESTERDAY, Date.from(today.minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.BEFORE_30_DAYS, Date.from(today.minusDays(30).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        LocalDate lastWeekStart = today.with(TemporalAdjusters.previous(DayOfWeek.SUNDAY));
        lastWeekStart = lastWeekStart.minusDays(7 - ps.getInt(PreferenceConstants.START_WEEKDAY));
        if (lastWeekStart.plusDays(7).isAfter(today)) {
            lastWeekStart = lastWeekStart.minusDays(7);
        }
        map.put(TraceDetectedDateFilterEnum.LAST_WEEK_START, Date.from(lastWeekStart.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.LAST_WEEK_END, Date.from(lastWeekStart.plusDays(6).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.THIS_WEEK_START, Date.from(lastWeekStart.plusDays(7).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.THIS_WEEK_END, Date.from(lastWeekStart.plusDays(13).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        int termStartMonth = IntStream.range(0, OtherPreferencePage.MONTHS.length)
                .filter(i -> ps.getString(PreferenceConstants.TERM_START_MONTH).equals(OtherPreferencePage.MONTHS[i])).findFirst().orElse(-1);
        int half_1st_month_s = ++termStartMonth;
        int thisYear = today.getYear();
        // int thisMonth = today.getMonthValue(); // 元の仕様の場合はこのコメント解除
        // half 1st start
        LocalDate half_1st_month_s_date = null;
        // if (half_1st_month_s + 5 < thisMonth) { // 元の仕様の場合はこのコメント解除
        half_1st_month_s_date = LocalDate.of(thisYear, half_1st_month_s, 1);
        // } else { // 元の仕様の場合はこのコメント解除
        // half_1st_month_s_date = LocalDate.of(thisYear - 1, half_1st_month_s, 1); //
        // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(TraceDetectedDateFilterEnum.HALF_1ST_START, Date.from(half_1st_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        // half 1st end
        // LocalDate half_1st_month_e_date =
        // half_1st_month_s_date.plusMonths(6).minusDays(1);
        map.put(TraceDetectedDateFilterEnum.HALF_1ST_END, Date.from(half_1st_month_s_date.plusMonths(6).minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        // half 2nd start
        LocalDate half_2nd_month_s_date = half_1st_month_s_date.plusMonths(6);
        // half 2nd end
        LocalDate half_2nd_month_e_date = half_2nd_month_s_date.plusMonths(6).minusDays(1);
        // int todayNum =
        // Integer.valueOf(today.format(DateTimeFormatter.ofPattern("yyyyMMdd"))); //
        // 元の仕様の場合はこのコメント解除
        // int termEndNum =
        // Integer.valueOf(half_2nd_month_e_date.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
        // // 元の仕様の場合はこのコメント解除
        // if (todayNum < termEndNum) { // 元の仕様の場合はこのコメント解除
        // half_2nd_month_s_date = half_2nd_month_s_date.minusYears(1); //
        // 元の仕様の場合はこのコメント解除
        // half_2nd_month_e_date = half_2nd_month_e_date.minusYears(1); //
        // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(TraceDetectedDateFilterEnum.HALF_2ND_START, Date.from(half_2nd_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.HALF_2ND_END, Date.from(half_2nd_month_e_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        return map;
    }

    public void setWindowTitle() {
        String text = null;
        List<Organization> validOrgs = getValidOrganizations();
        if (!validOrgs.isEmpty()) {
            List<String> orgNameList = new ArrayList<String>();
            for (Organization validOrg : validOrgs) {
                orgNameList.add(validOrg.getName());
            }
            text = String.join(", ", orgNameList);
        }
        boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
        if (isSuperAdmin) {
            this.shell.setText(String.format(WINDOW_TITLE, "SuperAdmin"));
        } else {
            if (text == null || text.isEmpty()) {
                this.shell.setText(String.format(WINDOW_TITLE, "組織未設定"));
            } else {
                this.shell.setText(String.format(WINDOW_TITLE, text));
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("traceFilter".equals(event.getPropertyName())) {
            Map<FilterEnum, Set<Filter>> filterMap = (Map<FilterEnum, Set<Filter>>) event.getNewValue();
            traceTable.clearAll();
            traceTable.removeAll();
            filteredTraces.clear();
            selectedIdxes.clear();
            for (Button button : checkBoxList) {
                button.dispose();
            }
            checkBoxList.clear();
            if (isFirstDetectSortDesc) {
                Collections.reverse(traces);
            } else {
                Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                    @Override
                    public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                        return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                    }
                });
            }
            for (ItemForVulnerability vul : traces) {
                boolean lostFlg = false;
                for (Filter filter : filterMap.get(FilterEnum.RULE_NAME)) {
                    if (vul.getVulnerability().getRuleName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.SEVERITY)) {
                    if (vul.getVulnerability().getSeverity().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.APP_NAME)) {
                    if (vul.getVulnerability().getApplication().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.ORG_NAME)) {
                    if (vul.getVulnerability().getOrg().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.STATUS)) {
                    if (vul.getVulnerability().getStatus().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.PENDING_STATUS)) {
                    if (vul.getVulnerability().getPendingStatus() != null && vul.getVulnerability().getPendingStatus().getStatus().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                if (!lostFlg) {
                    addColToVulnTable(vul, -1);
                    filteredTraces.add(vul);
                }
            }
            traceCount.setText(String.format("%d/%d", filteredTraces.size(), traces.size()));
        } else if ("tsv".equals(event.getPropertyName())) {
            System.out.println("tsv main");
        }

    }

    /**
     * @param listener
     */
    public synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
        this.support.addPropertyChangeListener(listener);
    }

    /**
     * @param listener
     */
    public synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
        this.support.removePropertyChangeListener(listener);
    }
}
