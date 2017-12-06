package server.ignition;

import com.sun.org.apache.xpath.internal.operations.Bool;
import databases.paginator.ListBox;
import delayed.managers.PushManager;
import org.apache.commons.io.FileUtils;
import server.comm.DataMap;
import server.comm.RestProcessor;
import server.response.Response;
import server.response.ResponseConst;
import server.rest.DataMapUtil;
import server.rest.RestConstant;
import server.rest.RestUtil;
import services.CommonSVC;
import services.UserSVC;
import spark.ModelAndView;
import spark.Service;
import spark.TemplateEngine;
import spark.utils.IOUtils;
import utils.Log;
import utils.MailSender;

import javax.servlet.MultipartConfigElement;
import javax.servlet.http.Part;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

/**
 * @author 함의진
 * @version 2.0.0
 * 서버 실행을 위한 이그니션 클래스
 * @description (version 2.5.0) Response Transformer refactored with the lambda exp. and BaseIgniter applied
 * Jul-21-2017
 */
public class ServiceIgniter extends BaseIgniter{

    private Service service;

    private CommonSVC commonSVC;
    private UserSVC userSVC;

    /**
     * 서버 실행에 필요한 전처리 작업을 위한 init 파트
     * utils 패키지가 포함하는 유틸리티 싱글턴의 경우, 이곳에서 상수로서 값을 전달하고, 존재하거나 초기화되었을 경우에 한해 인스턴스를 반환하도록
     * 별도로 인스턴스 취득자를 구성하였다.
     */
    {
        commonSVC = new CommonSVC();
        userSVC = new UserSVC();
        try {
            MailSender.start("euijin.ham@richware.co.kr", "gpswpf12!", 20);
            PushManager.start("AAAAWeDYee8:APA91bF8xbiIZMJdMyTuF9CciacPhwEAzn7qFN3jGPKvKoRr1y_rlXthzZTT8MzHCG3l3LFti5lo-H3Rt6n7VcpddPr69N8sCSkEvTiARHvhl4f5zVqn5Yq9CVWN8vDW2UiC-5dFx_0C");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static ServiceIgniter instance;

    public static ServiceIgniter getInstance() {
        if (instance == null) instance = new ServiceIgniter();
        return instance;
    }

    /**
     * 모든 이그니터는 그의 슈퍼클래스로서 베이스 이그니터를 상속받으며, 자동적으로 API 문서를 생성한다.
     * API에 대한 Description은 REST 명시 시 별도 인자로 전달하여 구성할 수 있으며, 구성하지 않을 경우, 공백으로 표시된다.
     */
    public void igniteServiceServer() {

        setProjectName("Kopas");
        setDeveloper("EuiJin.Ham");
        setCallSample("http://192.168.0.101:10040");
        setDebugMode(true);

        service = Service.ignite().port(RestConstant.REST_SERVICE);

        service.before((req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            Log.e("Connection", "Service Server [" + Calendar.getInstance().getTime().toString() + "] :: [" + req.pathInfo() + "] FROM [" + RestUtil.extractIp(req.raw()) + "] :: " + map);
            res.type(RestConstant.RESPONSE_TYPE_JSON);
        });

        super.enableCORS(service, "*", "GET, PUT, DELETE, POST, OPTIONS", "Access-Control-Allow-Origin, Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

        super.get(service, "/system", (req, res) -> new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, System.getenv()), "서버 시스템 환경을 확인하기 위한 API 입니다.");

        super.post(service, "/web/user/check/password", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());

            if(DataMapUtil.isValid(map, "email", "password")){
                final String id = map.getString("email");
                final String password = map.getString("password");

                DataMap user = userSVC.checkPassword(id, password);

                if(user == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
                else {
                    DataMapUtil.mask(user, "password");
                    return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, user);
                }
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 비밀번호 검증을 위한 API 입니다.", "email", "password");

        super.get(service, "/device/filter/beacon", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final String beaconList = map.getString("csv");
            List<String> filtered = commonSVC.filterBeacon(beaconList);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, filtered);
        }, "KOPAS 측 비콘만을 필터링하기 위한 API 입니다. 비콘의 UUID만을 CSV 값으로 전송하면, KOPAS 측 비콘이 String 리스트로 반환됩니다.", "csv");

        super.post(service, "/web/user/access", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());

            if(DataMapUtil.isValid(map, "email", "token")){
                final String id = map.getString("email");
                final String token = map.getString("token");

                DataMap user = userSVC.loginWithApprovalToken(id, token);

                if(user == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
                else {
                    DataMapUtil.mask(user, "password");
                    return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, user);
                }
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 액세스 토큰 로그인을 위한 API 입니다.", "email", "token");

        super.post(service, "/web/user/login", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());

            if(DataMapUtil.isValid(map, "email", "password")){
                final String id = map.getString("email");
                final String password = map.getString("password");

                DataMap user = userSVC.loginWeb(id, password);

                if(user == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
                else {
                    DataMapUtil.mask(user, "password");
                    return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, user);
                }
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 로그인을 위한 API 입니다.", "email", "password");

        super.post(service, "/web/user/update/name/:id", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final int id = Integer.parseInt(req.params(":id"));
            if(DataMapUtil.isValid(map, "name")) {
                final String newVal = map.getString("name");
                final DataMap retVal = userSVC.changeName(id, newVal);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }
            return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
        }, "사용자 이름 변경을 위한 API 입니다.", "id[REST]", "name");

        super.post(service, "/web/user/update/phone/:id", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final int id = Integer.parseInt(req.params(":id"));
            if(DataMapUtil.isValid(map, "phone")) {
                final String newVal = map.getString("phone");
                final DataMap retVal = userSVC.changePhone(id, newVal);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }
            return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
        }, "사용자 휴대폰 번호 변경을 위한 API 입니다.", "id[REST]", "phone");

        super.post(service, "/web/user/update/password/:id", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final int id = Integer.parseInt(req.params(":id"));
            if(DataMapUtil.isValid(map, "password")) {
                final String newPassword = map.getString("password");
                userSVC.changePassword(id, newPassword);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
            }
            return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
        }, "사용자 비밀번호 변경을 위한 API 입니다.", "id[REST]", "password");

        super.post(service, "/web/user/push/on/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOnPush(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 푸시 수신 여부(수신)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/web/user/push/off/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOffPush(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 푸시 수신 여부(미수신)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/web/user/alarm/on/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOnAlarm(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 알람 수신 여부(수신)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/web/user/alarm/off/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOffAlarm(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 알람 수신 여부(미수신)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/web/user/gesture/on/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOnGesture(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 제스쳐 사용 여부(사용)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/web/user/gesture/off/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = userSVC.turnOffGesture(id);
            if(map == null) return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, map);
        }, "사용자 설정 - 제스쳐 사용 여부(미사용)를 설정하기 위한 API 입니다.", "id[REST]");

        super.post(service, "/device/user/init", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());

            if(DataMapUtil.isValid(map, "memberId")){
                final int memberId = map.getInt("memberId");
                if(DataMapUtil.isValid(map, "deviceType", "regKey", "lastIp")){
                    userSVC.initUser(map);
                    return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, userSVC.getUserByKey(memberId));
                }else{
                    return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
                }
            }
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, "There is no valid member id. Ignoring this request. :(");
        }, "<p class='emp'>디바이스</p>앱 실행 시 마다 호출되는 시작 프로세스로 memberId가 없을 경우, 업데이트를 수행하지 않습니다. 정상 업데이트의 경우, 회원정보가 반환됩니다.",
                "memberId", "regKey", "deviceType", "lastIp");

        super.post(service, "/web/user/join", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "email", "password", "name", "phone", "deviceType", "regKey", "lastIp")){
                final int retCode = userSVC.joinWeb(map, req.host());

                if(retCode == ResponseConst.CODE_SUCCESS) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else if(retCode == ResponseConst.CODE_ALREADY_EXIST) return new Response(ResponseConst.CODE_ALREADY_EXIST, ResponseConst.MSG_ALREADY_EXIST);
                else return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 회원가입을 위한 API입니다. <b>본 API를 통해 호출 시 대기회원으로 저장됩니다.</b>",
                "email", "password", "name", "phone", "deviceType", "regKey", "lastIp");

        super.get(service, "/web/user/find/email", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "name", "phone")){
                final String name = map.getString("name");
                final String phone = map.getString("phone");
                DataMap retVal = userSVC.findEmail(name, phone);
                if(retVal == null) return new Response(ResponseConst.CODE_NOT_EXISTING, ResponseConst.MSG_NOT_EXISTING);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 이메일 찾기를 위한 API이며, 패스워드가 마스킹된 회원 정보 전체가 반환됩니다.", "name", "phone");

        super.get(service, "/web/user/find/password", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "name", "phone", "email")){

                boolean isExisting = userSVC.findPassword(map);
                if(isExisting) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_NOT_EXISTING, ResponseConst.MSG_NOT_EXISTING);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "직원용 APP 비밀번호 찾기를 위한 API입니다.", "email", "name", "phone");

        super.link(service, "/approval/:code", (req, res) -> {
            final String code = req.params(":code");
            boolean succ = userSVC.authEmailApprovalCode(code);
            res.type(RestConstant.RESPONSE_TYPE_HTML);
            if(succ) {
                return RestConstant.getJSAlertAndClose("정상적으로 처리되었습니다.");
            }
            else {
                return RestConstant.getJSAlertAndClose("잘못된 접근입니다.");
            }
        }, "이메일 인증 링크 접속 시 호출되는 REST API입니다. <b>웹에서 명시 호출하지 않습니다.</b>", "code[REST]");

        super.get(service, "/info/region", (req, res) -> {
            List<DataMap> retVal = commonSVC.getSidoList();
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "시/도 목록을 취득하기 위한 API입니다.");

        super.get(service, "/info/region/:sidoID", (req, res) -> {
            final int sidoID = Integer.parseInt(req.params(":sidoID"));
            List<DataMap> retVal = commonSVC.getGugunList(sidoID);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "시/군/구 목록을 취득하기 위한 API입니다.", "sidoID[REST]");

        super.get(service, "/info/company", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final int page = map.getInt("page", 1);
            final int limit = map.getInt("limit", 10);
            final String search = map.getString("search", "");
            final int sido = map.getInt("sido", -1);
            final int gungu = map.getInt("gungu", -1);

            ListBox retVal = commonSVC.getCompanyList(page, limit, search, sido, gungu);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "근무지 목록을 취득하기 위한 API입니다. 시/도 번호 혹은 시/군/구 번호와 상호를 통해 검색할 수 있으며, 전체 범위는 <b>-1</b>로 약속합니다.",
                "page[Optional]", "limit[Optional]", "search[Optional]", "sido[Optional]", "gungu[Optional]");

        super.post(service, "reg/invite", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
        }, "<font color=red><b class='emp'>미구현</b></font> 초대장 작성을 위한 API입니다. 인가된 사용자만 본 기능을 호출하도록 구현되어야 합니다.",
                "memberId");

        super.get(service, "/info/board/:mode", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            final int mode = Integer.parseInt(req.params(":mode"));
            final int page = map.getInt("page", 1);
            final int limit = map.getInt("limit", 10);
            final String search = map.getString("search", "");
            final int company = map.getInt("company", -1);
            if(mode != 0 && company != -1){
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
            ListBox retVal = commonSVC.getBoardList(page, limit, company, search, mode);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "게시판 글 목록을 취득하기 위한 API 입니다. REST 파라미터인 :mode에 타입을 전송하면 그에 맞는 게시판 글이 리스팅됩니다. [0:Notice/1:FAQ/2:Q&A]",
                "mode[REST]", "page[Optional]", "limit[Optional]", "search[Optional]", "company[Integral/Must be -1 when the mode is not 0]");
        // TODO the way to generate accessToken and authorize the devices without abusing

        super.get(service, "/info/board/detail/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            final DataMap retVal = commonSVC.getBoard(id);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "게시판 글 상세정보를 취득하기 위한 API 입니다. REST 파라미터인 :id에 글 번호를 전송하면 이의 상세정보와 이전/다음글의 정보가 함께 표시됩니다.", "id[REST]");

        super.get(service, "/info/workplace/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            final List<DataMap> retVal = userSVC.getWorkplaces(id);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "일반 사용자의 근무지 목록을 취득하기 위한 API 입니다.", "id[REST]");

        super.get(service, "/info/workplace/detail/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            final DataMap retVal = userSVC.getWorkplace(id);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "근무지 상세정보를 취득하기 위한 API 입니다. REST 파라미터인 :id에 근무지 번호를 전송하면 이의 상세 정보가 표시됩니다", "id[REST]");

        super.get(service, "/info/workplace/admin/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            final DataMap retVal = userSVC.getWorkplaceAdmin(id);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "근무지의 관리자를 취득하기 위한 API 입니다. REST 파라미터인 :id에 근무지 번호를 전송하면 해당하는 관리자를 반환합니다.", "id[REST]");

        super.post(service, "/delete/workplace/:id", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "companyId")) {
                int company = map.getInt("companyId");
                int userId = Integer.parseInt(req.params(":id"));
                boolean succ = userSVC.deleteWorkplace(userId, company);
                if (succ) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_FAILURE, ResponseConst.MSG_FAILURE);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "사용자의 근무지 삭제를 위한 API 입니다. REST 파라미터를 통해 사용자 번호를 전송하고, 삭제하고자 하는 회사의 키를 함께 전송해야 합니다.",
                "id[REST]", "companyId");

        super.get(service, "/info/company/:id", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "companyId")) {
                int companyId = Integer.parseInt(req.params(":id"));
                int userId = map.getInt("userId");
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "어머", "");

        super.post(service, "/reg/workplace/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "companyId", "permission")){
                final int memberId = id;
                final int companyId = map.getInt("companyId");
                final int permission = map.getInt("permission");
                final DataMap retVal = userSVC.addWorkplace(memberId, companyId, permission);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "사용자의 근무지 등록을 위한 API 입니다. REST 파라미터를 통해 사용자 번호를 전송하고, 등록하고자 하는 회사의 키와 권한를 함께 전송해야 합니다.",
                "id[REST]", "companyId", "permission[H:100/M:110/L:120/U:130]");

        //TODO 승인코드 발급 및 DB처리
        super.post(service, "/confirm/workplace/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "companyId", "token")){
                final int memberId = id;
                final int companyId = map.getInt("companyId");
                final String token = map.getString("token");
                final Boolean retVal = userSVC.confirmWorkplaceToken(memberId, companyId, token);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "사용자가 등록한 근무지에 대한 승인코드 확인 API 입니다. REST 파라미터를 통해 사용자 번호를 전송하고, 승인하고자 하는 회사의 키와 토큰을 전송해야 합니다.",
                "id[REST]", "companyId", "token");

        super.post(service, "/gesture/gate/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "gateId")){
                final int memberId = id;
                final int gateId = map.getInt("gateId");
                final boolean succ = userSVC.gestureDoor(memberId, gateId);
                if(succ) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_ALREADY_EXIST, ResponseConst.MSG_ALREADY_EXIST);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_FAILURE);
            }

        }, "출입문 제스처 허용을 위한 API 입니다. REST 파라미터로 사용자 번호를 전송하고, 해당 번호에 할당된 값이 있는 경우 실패를 반환하고, 없는 경우 등록합니다.",
                "id[REST]", "gateId");

        super.post(service, "/undogesture/gate/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "gateId")){
                final int memberId = id;
                final int gateId = map.getInt("gateId");
                final boolean succ = userSVC.undoGestureDoor(memberId, gateId);
                if(succ) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_NOT_EXISTING, ResponseConst.MSG_NOT_EXISTING);
            }
            else return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
        }, "출입문 제스처 비활성을 위한 API 입니다. REST 파라미터로 사용자 번호를 전송하고, 기존에 허용된 문이 없는 경우 실패를 반환하고, 있는 경우 삭제합니다.",
                "id[REST", "gateId");

        super.post(service, "/like/gate/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "gateId")){
                final int memberId = id;
                final int gateId = map.getInt("gateId");
                final boolean succ = userSVC.likeDoor(memberId, gateId);
                if(succ) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_ALREADY_EXIST, ResponseConst.MSG_ALREADY_EXIST);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "출입문 즐겨찾기를 위한 API 입니다. 즐겨찾기가 10개 이상인 경우, 실패를 반환하며, 이미 존재하는 경우, 업데이트합니다.", "id[REST]", "gateId");

        super.post(service, "/unlike/gate/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "gateId")){
                final int memberId = id;
                final int gateId = map.getInt("gateId");
                final boolean succ = userSVC.unlikeDoor(memberId, gateId);
                if(succ) return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
                else return new Response(ResponseConst.CODE_NOT_EXISTING, ResponseConst.MSG_NOT_EXISTING);
            }
            else return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);

        }, "REST 파라미터로 받은 회원의 출입문 즐겨찾기 해제를 위한 API 입니다. ", "id[REST]", "gateId");

        super.get(service, "/info/gates/:companyId", (req, res) -> {
            final int companyId = Integer.parseInt(req.params(":companyId"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "memberId")){
                final int memberId = map.getInt("memberId");
                final List<DataMap> retVal = userSVC.getGateList(companyId, memberId);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "한 근무지의 출입문 리스트를 취득하기 위한 API 입니다. REST 파라미터는 회사의 근무지의 고유번호이며, 현재 로그인된 회원번호를 함께 전송하여야 합니다. (즐겨찾기 표시를 위해)",
                "companyId[REST]", "memberId");

        super.get(service, "/info/gates/favored/:id", (req, res) -> {
            final int memberId = Integer.parseInt(req.params(":id"));
            final List<DataMap> retVal = userSVC.getFavoredGateList(memberId);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "REST 파라미터로 받은 멤버가 즐겨찾기한 출입문 리스트를 취득하기 위한 API.", "id[REST]");

        super.get(service, "/info/gates", (req, res) -> {
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "beaconSN", "major", "minor")){
                final String beaconSN = map.getString("beaconSN").trim();
                final int major = map.getInt("major");
                final int minor = map.getInt("minor");
                final List<DataMap> retVal = commonSVC.getGatesByBeacon(beaconSN, major, minor);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "비콘의 UUID를 통해 해당 장치에 연결된 출입문 리스트를 반환합니다. <p class='emp'>위 API 와 유사하니 혼동에 주의하시기 바랍니다.</p>",
                "beaconSN", "major", "minor");

        //TODO 출입문 상태(정상/에러)
        super.get(service, "/info/gate/detail/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "memberId")){
                final int gateId = id;
                final int memberid = map.getInt("memberId");

                final DataMap retVal = userSVC.getGateDetail(gateId, memberid);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "출입문 상세정보 반환 API", "id[REST]", "memberId");

        super.get(service, "/info/diligence/latest/company/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "companyId")){
                final int memberId = id;
                final int companyId = map.getInt("companyId");

                final DataMap retVal = userSVC.getLatestDiligenceCompany(memberId, companyId);
                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "REST 파라미터로 받은 멤버가 companyId에 해당하는 회사에 가장 최근 출입한 기록을 불러옵니다", "id[REST]", "companyId");

        super.get(service, "/info/diligence/latest/user/:id", (req, res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());

            final int memberId = id;
            final DataMap retVal = userSVC.getLatestDiligenceUser(memberId);
            return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS, retVal);
        }, "REST 파라미터로 받은 멤버의 가장 최근 출입기록을 불러옵니다.", "id[REST]");

        super.post(service, "/reg/diligence/:id", (req,  res) -> {
            final int id = Integer.parseInt(req.params(":id"));
            DataMap map = RestProcessor.makeProcessData(req.raw());
            if(DataMapUtil.isValid(map, "gateId", "classifier", "type")){
                final int memberId = id;
                final int gateId = map.getInt("gateId");
                final int classifier = map.getInt("classifier");
                final int type = map.getInt("type");
                final boolean result = userSVC.manipulateDiligence(memberId, gateId, classifier, type);

                return new Response(ResponseConst.CODE_SUCCESS, ResponseConst.MSG_SUCCESS);
            }else{
                return new Response(ResponseConst.CODE_INVALID_PARAM, ResponseConst.MSG_INVALID_PARAM);
            }
        }, "한 출입문에 대해 출근/퇴근 처리를 진행합니다. REST 파라미터로 받은 유저를 대상으로 출근/퇴근 투플을 삽입합니다.",
                "id[REST]", "gateId", "classifier", "type");

        /**
         * 이미지 업로드 모듈 테스트임 - 관리자 API 개발 시 진행 예정
         */
        super.post(service, "/upload/file", (req, res) -> {
            req.attribute("org.eclipse.jetty.multipartConfig", new MultipartConfigElement("./upload"));
            Part filePart = req.raw().getPart("myfile");

            try (InputStream inputStream = filePart.getInputStream()) {
                OutputStream outputStream = new FileOutputStream(RestConstant.UPLOAD_PATH + filePart.getSubmittedFileName());
                IOUtils.copy(inputStream, outputStream);
                outputStream.close();
            }

//            FileUtils.forceMkdir();

            return "File uploaded and saved.";
        }, "<b class='emp'>테스트용 API 입니다. 호출금지!!!</b>");

    }

}
