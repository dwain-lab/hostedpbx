create or replace PACKAGE BODY         PCK_PBX AS 

FUNCTION FN_POST_AUTHENTICATE (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2,vi_t_username VARCHAR2, VO_TOKEN OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER AS
    VV_HTTP_URL       VARCHAR2(2000); 
    VV_HTTP_PARAMETER VARCHAR2(2000);
    VV_STATUS         VARCHAR2(1000):= NULL;
    VV_Token          VARCHAR2(2000):= NULL; 
    VV_Message        VARCHAR2(2000):= NULL;
    VV_HTTP_STATUS VARCHAR2(100);
    VV_HTTP_RESPONSE VARCHAR2(20000);

    --INTERFACE VARIABLES
    VV_MID_ID_USER NUMBER := 1; 
    VV_LOG_MESSAGE VARCHAR2(2000);
    VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID NUMBER;
    VV_DO_LOG CHAR; 
    VV_NAME_INTERFACE VARCHAR2(24) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE NUMBER; 
    VV_ID_CODSYSTEM NUMBER;

BEGIN 

  --INTERFACE DATA
    SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
    SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
    SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF (VV_MID_ID_USER < 0) THEN
      VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
      PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
      RETURN VO_RESULT;
    END IF;
    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA

    --VV_HTTP_URL      :=GV_HTTP_URL;
    VV_HTTP_URL      := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --dbms_output.put_line(VV_HTTP_URL);
    --VV_HTTP_PARAMETER:=GV_HTTP_PARAMETER;
    VV_HTTP_PARAMETER:= 'key='||GV_KEY;
    --dbms_output.put_line(VV_HTTP_PARAMETER);

    MIDWARE.TEST_HTTP_POST(VV_HTTP_URL, VV_HTTP_PARAMETER, VV_HTTP_STATUS, VV_HTTP_RESPONSE);
    --dbms_output.put_line(HTTP_RESPONSE);

    --SELECT json_value(HTTP_RESPONSE, '$.status'), json_value(HTTP_RESPONSE, '$.data.token') into VV_STATUS, VV_Token FROM dual;

   SELECT json_value(VV_HTTP_RESPONSE, '$.status') into VV_STATUS FROM dual;
   --VO_STATUS:=VV_STATUS;

   If VV_STATUS = 'success' THEN 
        SELECT json_value(VV_HTTP_RESPONSE, '$.data.token') into VV_Token FROM dual;
        VO_TOKEN:=VV_TOKEN;
    ELSE 
        SELECT json_value(VV_HTTP_RESPONSE, '$.message') into VV_Message FROM dual;
        VO_RESULT := -5000;
        VO_MESSAGE := 'Error: Tenant Authentication Unsuccessful';        
        RETURN VO_RESULT;
    END IF; 

    VO_RESULT:=0;
    VO_MESSAGE:='SUCCESS';    
    --DBMS_OUTPUT.PUT_LINE ('Status :'||VV_STATUS||' Message :'||VV_Message||' Token :'||VV_Token);   
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
  EXCEPTION 
   WHEN OTHERS
  THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
   RETURN VO_RESULT;
END FN_POST_AUTHENTICATE; 

FUNCTION fn_add_trunk_cpbx ( 
    vi_username    IN   VARCHAR2, 
    vi_password    IN   VARCHAR2,
    vi_ip_info     IN   VARCHAR2,
    vi_t_username  IN   VARCHAR2,
    vi_t_password  IN   VARCHAR2,
    vi_product     IN   VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER  
) RETURN NUMBER AS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES   

--PROGRAM VARIABLES
    vv_description           VARCHAR(20) := '%2B501'||vi_t_username;
    vv_outgoing_username     VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_username
    vv_outgoing_defaultuser  VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_defaultuser
    vv_outgoing_remotesecret VARCHAR(50) := vi_t_password; --outgoing_remotesecret
    vv_outgoing_fromuser     VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_fromuser
    vv_trunk_cid             VARCHAR(50) := '%2B501'||vi_t_username; --trunk_cid
    http_status              VARCHAR2(3);
    http_url                 VARCHAR(1000);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
    http_url_authenticate    VARCHAR2(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
--    http_url_authenticate    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --http_url_create_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/create_trunk';
    http_url_create_trunk    VARCHAR(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
--    http_url_create_trunk    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
    http_parameter           VARCHAR2(1000);
    http_response            VARCHAR2(12000);
    vo_post_auth_result      NUMBER;
    vo_post_auth_message     VARCHAR2(1000);
    vo_post_auth_token       VARCHAR2(1000);
    add_trunk_u2000_result   NUMBER;
    add_trunk_u2000_message  VARCHAR(500);
    add_trunk_helper_cpbx_result NUMBER;
    add_trunk_helper_cpbx_message VARCHAR(500);
--END PROGRAM VARIABLES

--Remove Global Variable use in stand alone function
--    gv_codsystem          VARCHAR2(20) := 'HOSTED';
BEGIN

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vv_log_message := vi_ip_info;
--END INTERFACE DATA

--NUMERIC VALIDATION
    IF NOT REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$')  THEN
        VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
        VO_RESULT := -1021;
        RETURN VO_RESULT;
    END IF;

    add_trunk_helper_cpbx_result := pck_pbx.fn_add_trunk_helper_cpbx (vi_username, vi_password, vi_ip_info, vi_t_username, vi_t_password, vi_product, add_trunk_helper_cpbx_message, add_trunk_helper_cpbx_result);

    IF (add_trunk_helper_cpbx_result = -2001) THEN
        VO_MESSAGE := 'error: Unable to proccess request due to pbx not created';
        VO_RESULT := -2041;

        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution
        RETURN VO_RESULT;
    END IF;

    add_trunk_u2000_result := pck_pbx.fn_add_trunk_u2000 (vi_username, vi_password, vi_ip_info, vi_t_username, add_trunk_u2000_message, add_trunk_u2000_result);

    IF (add_trunk_u2000_result = 0 AND add_trunk_helper_cpbx_result = 0) THEN
        VO_MESSAGE := 'Success';
        VO_RESULT := 0;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution
        RETURN VO_RESULT;
    ELSIF(add_trunk_u2000_result != 0 AND add_trunk_helper_cpbx_result = 0) THEN
        VO_MESSAGE := 'partial success: success: cpbx | '||'error: U2000 code:'||add_trunk_u2000_result||'cpbx message:'||add_trunk_u2000_message;
        VO_RESULT := -6000;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution
        RETURN VO_RESULT;
    ELSIF(add_trunk_helper_cpbx_result != 0 AND add_trunk_u2000_result = 0) THEN
        VO_MESSAGE := 'partial success: success: U2000 | '||'error: cpbx code:'||add_trunk_helper_cpbx_result||'cpbx message:'||add_trunk_helper_cpbx_message;
        VO_RESULT := -6000;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution
        RETURN VO_RESULT;
    ELSE
        VO_MESSAGE := 'CPBX Error Code: '||add_trunk_helper_cpbx_result||'CPBX Error Message: '||add_trunk_helper_cpbx_message||' U2000 Error Code: '||add_trunk_u2000_result||' U2000 Error Message: '||add_trunk_u2000_message;
        VO_RESULT := -2041;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution
        RETURN VO_RESULT;
    END IF;

--When any errors then it logs the error
EXCEPTION
    WHEN OTHERS THEN
        vo_result := -8000;
        vo_message := sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                      || vi_ip_info
                                                      || ':'
                                                      || vo_message,
                                    vv_id_interface,
                                    vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        dbms_output.put_line(to_char($$plsql_line)
                             || ': '
                             || dbms_utility.format_error_stack
                             || dbms_utility.format_call_stack
                             || dbms_utility.format_error_backtrace); --TO DO: Log error with session call
        RETURN vo_result;
END fn_add_trunk_cpbx;

FUNCTION fn_add_trunk_helper_cpbx ( 
    vi_username    IN   VARCHAR2, 
    vi_password    IN   VARCHAR2,
    vi_ip_info     IN   VARCHAR2,
    vi_t_username  IN   VARCHAR2,
    vi_t_password  IN   VARCHAR2,
    vi_product     IN   VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER  
) RETURN NUMBER AS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES   

--PROGRAM VARIABLES
    vv_description           VARCHAR(20) := '%2B501'||vi_t_username;
    vv_outgoing_username     VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_username
    vv_outgoing_defaultuser  VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_defaultuser
    vv_outgoing_remotesecret VARCHAR(50) := vi_t_password; --outgoing_remotesecret
    vv_outgoing_fromuser     VARCHAR(50) := '%2B501'||vi_t_username; --outgoing_fromuser
    vv_trunk_cid             VARCHAR(50) := '%2B501'||vi_t_username; --trunk_cid
    vv_register              VARCHAR(400) := '%2B501'||vi_t_username||'%40'||GV_OUTGOING_HOST||'---mtob-'||GV_OUTBOUND_PROXY||'%3A'||vi_t_password||'%3A%2B501'||vi_t_username||'%40'||GV_OUTGOING_HOST||'%40'||GV_OUTBOUND_PROXY||'%3A'||GV_OUTGOING_PORT||'%2F%2B501'||vi_t_username; --register
    http_status              VARCHAR2(3);
    http_url                 VARCHAR(1000);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
    http_url_authenticate    VARCHAR2(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
--    http_url_authenticate    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --http_url_create_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/create_trunk';
    http_url_create_trunk    VARCHAR(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
--    http_url_create_trunk    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
    http_parameter           VARCHAR2(1000);
    http_response            VARCHAR2(12000);
    vo_post_auth_result      NUMBER;
    vo_post_auth_message     VARCHAR2(1000);
    vo_post_auth_token       VARCHAR2(1000);
    add_trunk_u2000_result   NUMBER;
    add_trunk_u2000_message  VARCHAR(100);
--END PROGRAM VARIABLES

--Remove Global Variable use in stand alone function
--    gv_codsystem          VARCHAR2(20) := 'HOSTED';
BEGIN

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vv_log_message := vi_ip_info;
--END INTERFACE DATA

    vo_post_auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username,
                                                       vo_post_auth_message,
                                                       vo_post_auth_token,
                                                       vo_post_auth_result);

    dbms_output.put_line(vo_post_auth_result);
    IF ( vo_post_auth_result = 0 ) THEN
        http_parameter := 'token='
                          || vo_post_auth_message
                          || '&technology='
                          || 'sip' --vi_product
                          || '&description='
                          || vv_description
                          || '&outgoing_username=%2B'
                          || vi_t_username
                          || '&outgoing_host='
                          || gv_outbound_proxy --gv_outgoing_host
                          || '&outgoing_port='
                          || gv_outgoing_port
                          || '&outgoing_username='
                          || vv_outgoing_username
                          || '&outgoing_defaultuser='
                          || vv_outgoing_defaultuser
                          || '&outgoing_remotesecret='
                          || vv_outgoing_remotesecret
                          || '&outgoing_fromuser='
                          || vv_outgoing_fromuser
                          || '&outgoing_fromdomain='
                          || gv_outgoing_fromdomain
                          || '&outbound_proxy='
                          || gv_outbound_proxy
                          || '&outgoing_type='
                          || gv_outgoing_type
                          || '&outgoing_insecure='
                          || GV_OUTGOING_INSECURE
                          || '&trunk_cid=%22%22%20%3C%2B501'||vi_t_username||'%3E'
                          || '&register='
                          || vv_register
                          || '&register_flag=0';

        midware.test_http_post(http_url_create_trunk, http_parameter, http_status, http_response);

        IF ( instr(http_response, 'success') >= 1 ) THEN
            vo_result := 0;
            vo_message := 'success';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        ELSE
            vo_result := -2002;
            vo_message := http_response;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_t_password
                                 || '|'
                                 || vi_product
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result; 
        END IF;

    END IF;

    vo_result := -2001;
    vo_message := 'status:error, Unable to authenticate request.';
    dbms_output.put_line(to_char($$plsql_line)
                         || ': '
                         || vi_username
                         || '|'
                         || vi_password
                         || '|'
                         || vi_ip_info
                         || '|'
                         || vi_t_username
                         || '|'
                         || vi_t_password
                         || '|'
                         || vi_product
                         || '|'
                         || vo_message
                         || '|'
                         || vo_result);

    pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                vv_mid_id_user,
                                vv_exe_time);

    RETURN vo_result;

--When any errors then it logs the error
EXCEPTION
    WHEN OTHERS THEN
        vo_result := -8000;
        vo_message := sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                      || vi_ip_info
                                                      || ':'
                                                      || vo_message,
                                    vv_id_interface,
                                    vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        dbms_output.put_line(to_char($$plsql_line)
                             || ': '
                             || dbms_utility.format_error_stack
                             || dbms_utility.format_call_stack
                             || dbms_utility.format_error_backtrace); --TO DO: Log error with session call
        RETURN vo_result;
END fn_add_trunk_helper_cpbx;

FUNCTION fn_add_subscriber (
        vi_username    VARCHAR2,
        vi_password    VARCHAR2,
        vi_ip_info     VARCHAR2,
        vi_t_username  VARCHAR2,
        vi_plan        VARCHAR2,
        vo_message     OUT  VARCHAR2,
        vo_result      OUT  NUMBER
) RETURN NUMBER AS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    vv_hostname              VARCHAR2(25) := 'PBX-'||vi_t_username;
    vv_plan                  VARCHAR2(50);
    http_status              VARCHAR2(3);
    http_url                 VARCHAR(1000);
    http_parameter           VARCHAR2(1000);
    http_response            VARCHAR2(12000);
    vo_post_auth_result      INT;
    vo_post_auth_message     VARCHAR2(1000);
    vo_post_auth_token       VARCHAR2(1000);
    vv_plan2                        VARCHAR2(100);
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message; 

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;



    vv_log_message := vi_ip_info;
--END INTERFACE DATA

--        http_parameter := '
--    {
--        "action":"authenticate",
--        "username":"admin",
--        "password":"fWaBeeZYXmeKOZ"
--    }';
--
--    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,http_parameter, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);


    vv_plan2:=upper(vi_plan);

--NUMERIC VALIDATION
    IF NOT REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$')  THEN
        VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
        VO_RESULT := -2001;
    RETURN VO_RESULT;
    END IF;    

    IF ( vv_plan2 = 'S') THEN
        vv_plan := GV_PLAN_S;
    ELSIF ( vv_plan2 = 'M') THEN
        vv_plan := GV_PLAN_M;
    ELSIF ( vv_plan2 = 'L') THEN
        vv_plan := GV_PLAN_L;
    ELSE
        vo_result := -2002;
        vo_message := 'Error: Invalid plan';

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
        RETURN vo_result;
    END IF;
    vo_post_auth_result := pck_pbx.FN_POST_AUTHENTICATE_TENANT(vi_username, vi_password, vi_ip_info, vo_post_auth_token, vo_post_auth_message, vo_post_auth_result);

    IF ( vo_post_auth_result = 0 ) THEN
        http_parameter := '
        {
            "action":"create-tenant",
            "token":"'||vo_post_auth_token||'",
            "name":"'||vv_hostname||'",
            "image":"btl-cpbx-5.1.22.1",
            "resource_plan": "'||vv_plan||'",
            "system_name": "'||vv_hostname||'"            
        }';

        /*Removed as no longer necessary  "whitelist": [{"address":"172.21.56.33", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]},{"address":"172.21.56.30", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]}]*/

        MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,http_parameter, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);
        IF ( instr(http_response, 'pending') >= 1 ) THEN
            vo_result := 0;
            vo_message := 'success';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_plan
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        ELSE
            vo_result := -4010;
            vo_message := 'Error: Tenant already exists';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_plan
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        END IF;

    END IF;

    vo_result := -4000;
    vo_message := 'Error: MT Manger Authentication Unssuccessful';
    dbms_output.put_line(to_char($$plsql_line)
                         || ': '
                         || vi_username
                         || '|'
                         || vi_password
                         || '|'
                         || vi_ip_info
                         || '|'
                         || vi_t_username
                         || '|'
                         || vi_plan
                         || '|'
                         || vo_message
                         || '|'
                         || vo_result);

    pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                vv_mid_id_user,
                                vv_exe_time);

    RETURN vo_result;

--When any errors then it logs the error
EXCEPTION
    WHEN OTHERS THEN
        vo_result := -8000;
        vo_message := sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                      || vi_ip_info
                                                      || ':'
                                                      || vo_message,
                                    vv_id_interface,
                                    vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        dbms_output.put_line(to_char($$plsql_line)
                             || ': '
                             || dbms_utility.format_error_stack
                             || dbms_utility.format_call_stack
                             || dbms_utility.format_error_backtrace); --TO DO: Log error with session call
        RETURN vo_result;
END fn_add_subscriber;

FUNCTION FN_POST_AUTHENTICATE_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VO_T_TOKEN OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER AS


    --FUNCTION VARIABLES
    VV_HTTP_URL       VARCHAR2(2000);
    VV_HTTP_PARAMETER VARCHAR2(2000);
    VV_STATUS         VARCHAR2(1000);
    VV_Token          VARCHAR2(2000);
    VV_Message        VARCHAR2(2000);
    VV_HTTP_STATUS VARCHAR2(100);
    VV_HTTP_RESPONSE VARCHAR2(20000);
    --END FUNCTION VARIABLES

BEGIN


    VV_HTTP_URL      :=PCK_PBX.GV_HTTP_TENANT_URL;    
    VV_HTTP_PARAMETER:= '{"action":"authenticate","username":"admin","password":"fWaBeeZYXmeKOZ"}';

    MIDWARE.TEST_HTTP_POST(VV_HTTP_URL, VV_HTTP_PARAMETER, VV_HTTP_STATUS, VV_HTTP_RESPONSE);
    --dbms_output.put_line(HTTP_RESPONSE);

   SELECT json_value(VV_HTTP_RESPONSE, '$.status') into VV_STATUS FROM dual;


   If VV_STATUS = 'success' THEN 
        SELECT json_value(VV_HTTP_RESPONSE, '$.token') into /*VV_STATUS,*/ VV_Token FROM dual;
        VO_T_TOKEN:=VV_TOKEN;
    ELSE 
        SELECT json_value(VV_HTTP_RESPONSE, '$.error') into /*VV_STATUS,*/ VV_Message FROM dual;
        VO_RESULT := -4000;
        VO_MESSAGE := 'Error: MT Manger Authentication Unssuccessful';        
        RETURN VO_RESULT;
    END IF;
    VO_RESULT:=0;

   RETURN VO_RESULT;    
END FN_POST_AUTHENTICATE_TENANT;

FUNCTION FN_DELETE_SUBSCRIBER (VI_USERNAME IN VARCHAR2, VI_PASSWORD IN VARCHAR2, VI_IP_INFO IN VARCHAR2, VI_T_USERNAME IN VARCHAR2, VI_PRODUCT IN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT INT) 
RETURN NUMBER AS

--INTERFACE VARIABLES
    VV_MID_ID_USER        NUMBER := 1;
    VV_LOG_MESSAGE        VARCHAR2(2000);
    VV_EXE_TIME           NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID                NUMBER;
    VV_DO_LOG             CHAR;
    VV_NAME_INTERFACE     VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE       NUMBER;
    VV_ID_CODSYSTEM       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    VO_T_USERNAME            VARCHAR(50); 
    VO_TRUNK_ID              NUMBER;
    VO_FIND_RESULT           NUMBER;
    VO_FIND_MESSAGE          VARCHAR(100);
    HTTP_STATUS              VARCHAR2(3); 
    HTTP_URL                 VARCHAR(1000);
    HTTP_PARAMETER           VARCHAR2(1000);
    HTTP_RESPONSE            VARCHAR2(12000);
    VO_HTTP_RESPONSE_RESULT  INT;
    VO_HTTP_RESPONSE_MESSAGE VARCHAR2(1000);
    VO_POST_AUTH_RESULT      INT;
    VO_POST_AUTH_MESSAGE     VARCHAR2(1000);
    VO_POST_AUTH_TOKEN       VARCHAR2(1000);
    VO_U2000_DELETE_RESULT   INT;
    VO_U2000_DELETE_MESSAGE  VARCHAR2(1000);
    VO_GET                   INT;
    VO_GET_TENANTS           VARCHAR2(1000);
    VO_GET_MESSAGE           VARCHAR(100);
    VO_GET_RESULT            INT;

    HTTP_URL_AUTHENTICATE    VARCHAR2(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    HTTP_URL_DELETE_TRUNK    VARCHAR2(100) := 'https://PBX-'||vi_t_username||'.'||gv_http_url||'/destroy_trunk/';
    VO_T_PASSWORD            VARCHAR2(100);
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

        RETURN VO_RESULT;
    END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA


    --NULL VALIDATION
    IF VI_T_USERNAME IS NULL OR LENGTH (trim(VI_T_USERNAME)) = 0 THEN 
        VO_MESSAGE := 'Error: Trunk is missing';
        VO_RESULT := -2000;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                             VV_MID_ID_USER,
                             VV_EXE_TIME);
    RETURN VO_RESULT;
END IF;

    --NUMERIC VALIDATION
    IF NOT regexp_like ( VI_T_USERNAME, '^[0-9]+$') THEN
        VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
        VO_RESULT := -2001;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                             VV_MID_ID_USER,
                             VV_EXE_TIME);
    RETURN VO_RESULT;
END IF;
    
    VO_GET := PCK_PBX.FN_GET_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VO_GET_TENANTS,VO_GET_MESSAGE,VO_GET_RESULT);
    
    IF VO_GET_TENANTS NOT LIKE '%running%' THEN
        VO_U2000_DELETE_RESULT := PCK_PBX.FN_DELETE_TRUNK_U2000 (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VO_U2000_DELETE_MESSAGE, VO_U2000_DELETE_RESULT);
        dbms_output.PUT_LINE('THIS IF');
    ELSE

    --AUTHENTICATION Call
    VO_POST_AUTH_RESULT:= PCK_PBX.FN_POST_AUTHENTICATE(VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VO_POST_AUTH_TOKEN, VO_POST_AUTH_MESSAGE, VO_POST_AUTH_RESULT);                                                                     
    VO_FIND_RESULT:= PCK_PBX.FN_FIND_TRUNK (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VI_PRODUCT, VO_TRUNK_ID, VO_T_USERNAME, VO_T_PASSWORD, VO_FIND_RESULT, VO_FIND_MESSAGE);



    --Error result for FN_POST_AUTHENTICATE
    IF ( VO_POST_AUTH_RESULT != 0 ) THEN
        VO_RESULT := -5000;
        VO_MESSAGE := 'Error: Tenant Authentication Unsuccessful';   
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                             VV_MID_ID_USER,
                             VV_EXE_TIME);
    RETURN VO_RESULT;
END IF;

    --Error result for FN_FIND_TRUNK
    IF (VO_TRUNK_ID < 1 OR VO_TRUNK_ID IS NULL) THEN    
        VO_RESULT := -2050;
        VO_MESSAGE := 'Error: Trunk does not exist';
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                             VV_MID_ID_USER,
                             VV_EXE_TIME);
    RETURN VO_RESULT;
END IF;


    HTTP_URL := http_url_delete_trunk||VO_TRUNK_ID;
    HTTP_PARAMETER := 'token='|| VO_POST_AUTH_TOKEN;
    MIDWARE.TEST_HTTP_POST(HTTP_URL, HTTP_PARAMETER, HTTP_STATUS, HTTP_RESPONSE);

    VO_U2000_DELETE_RESULT := PCK_PBX.FN_DELETE_TRUNK_U2000 (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VO_U2000_DELETE_MESSAGE, VO_U2000_DELETE_RESULT);

        IF ( INSTR(HTTP_RESPONSE, 'success') >= 1 ) THEN
            VO_HTTP_RESPONSE_MESSAGE := 'SUCCESS';
            VO_HTTP_RESPONSE_RESULT := 0;
        ELSE 
            VO_HTTP_RESPONSE_RESULT := -5013;
            VO_HTTP_RESPONSE_MESSAGE := 'Error: Unable to delete trunk' ;
    END IF;

        --Error result for CPBX & U2000
        IF (VO_HTTP_RESPONSE_RESULT != VO_U2000_DELETE_RESULT ) THEN 
            VO_MESSAGE := 'CPBX: '||VO_HTTP_RESPONSE_MESSAGE||' CODE: '||VO_HTTP_RESPONSE_RESULT||'. U2000: '|| VO_U2000_DELETE_MESSAGE||' CODE: '||VO_U2000_DELETE_RESULT;
            VO_RESULT := -6000;
            PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                VV_MID_ID_USER,
                                VV_EXE_TIME);
        RETURN VO_RESULT;
   END IF;

    VO_MESSAGE := 'SUCCESS';
    VO_RESULT := 0;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                         VV_MID_ID_USER,
                         VV_EXE_TIME);
    END IF;
RETURN VO_RESULT;


--WHEN ANY ERRORS THEN IT LOGS THE ERROR
EXCEPTION
    WHEN OTHERS THEN
        VO_RESULT := -8000;
        VO_MESSAGE := SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, 'ERROR '
                                                      || VI_IP_INFO
                                                      || ':'
                                                      || VO_MESSAGE,
                                    VV_ID_INTERFACE,
                                    VV_ID_CODSYSTEM,
                                    VV_MID_ID_USER,
                                    VV_EXE_TIME);

        PCK_MIDDLE.MID_LOG_ERROR(VV_SID, SYSDATE, VV_ID_INTERFACE, VV_ID_CODSYSTEM, SQLERRM,
                                DBMS_UTILITY.FORMAT_ERROR_STACK,
                                DBMS_UTILITY.FORMAT_CALL_STACK || DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--STORE THE ERRORS OR PRESENT ALL ERRORS FOUND.
        DBMS_OUTPUT.PUT_LINE(TO_CHAR($$PLSQL_LINE)
                             || ': '
                             || DBMS_UTILITY.FORMAT_ERROR_STACK
                             || DBMS_UTILITY.FORMAT_CALL_STACK
                             || DBMS_UTILITY.FORMAT_ERROR_BACKTRACE); --TO DO: LOG ERROR WITH SESSION CALL
        RETURN VO_RESULT;
END FN_DELETE_SUBSCRIBER;

FUNCTION FN_GET_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_NUMBER VARCHAR2, VO_TENANTS OUT VARCHAR2,VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER AS

 --FUNCTION VARIABLES
    VV_HTTP_URL       VARCHAR2(2000);
    VV_HTTP_PARAMETER VARCHAR2(2000);
    VV_CNT            NUMBER (5, 0) := 0;
    VV_TENANTS        VARCHAR2(2000);
    VV_DID            VARCHAR(2000);
    VV_HTTP_STATUS    VARCHAR2(100);
    VV_HTTP_RESPONSE  VARCHAR2(30000);
    PBX_NUMBER        VARCHAR2(200) := 'PBX-'||VI_T_NUMBER;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
    VV_MID_ID_USER        NUMBER := 1;
    VV_LOG_MESSAGE        VARCHAR2(2000);
    VV_EXE_TIME           NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID                NUMBER;
    VV_DO_LOG             CHAR;
    VV_NAME_INTERFACE     VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE       NUMBER;
    VV_ID_CODSYSTEM       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    HTTP_STATUS                     VARCHAR2(3);
    HTTP_URL                        VARCHAR(1000);
    HTTP_PARAMETER                  VARCHAR2(1000);
    HTTP_RESPONSE                   VARCHAR2(12000);
    VO_POST_AUTH_TENANT_TOKEN       VARCHAR2(1000);
    VO_POST_AUTH_TENANT_MESSAGE     VARCHAR2(1000);
    VO_POST_AUTH_TENANT_RESULT      INT;
    VO_GET_RESOURCE_PLAN_NM         INT;
    VO_GET_PLAN_NM                  VARCHAR2(1000);
    VO_GET_RESOURCE_PLAN_MESSAGE    VARCHAR2(1000);
    VO_GET_RESOURCE_PLAN_RESULT     VARCHAR2(1000);
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

    RETURN VO_RESULT;
END IF;


    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA


--NULL VALIDATION
    IF VI_T_NUMBER IS NULL OR LENGTH (trim(VI_T_NUMBER)) = 0 THEN 
        VO_MESSAGE := 'Error: Trunk is missing';
        VO_RESULT := -2000;
    RETURN VO_RESULT;
END IF;

--NUMERIC VALIDATION
    IF NOT regexp_like ( VI_T_NUMBER, '^[0-9]{7}$') THEN
        VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
        VO_RESULT := -2001;
    RETURN VO_RESULT;
END IF;

  --AUTHENTICATION Call
  VO_POST_AUTH_TENANT_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VO_POST_AUTH_TENANT_TOKEN, VO_POST_AUTH_TENANT_MESSAGE, VO_POST_AUTH_TENANT_RESULT);

  DBMS_OUTPUT.PUT_LINE(VO_POST_AUTH_TENANT_MESSAGE);
    IF ( VO_POST_AUTH_TENANT_RESULT = 0 ) THEN
         HTTP_URL := PCK_PBX.GV_HTTP_TENANT_URL; 
         HTTP_PARAMETER:= '{"action":"tenants",'||'"token":"'||VO_POST_AUTH_TENANT_TOKEN||'"}';

    MIDWARE.MID_HTTP_POST(HTTP_URL, HTTP_PARAMETER, 'application/json', VV_HTTP_STATUS, VV_HTTP_RESPONSE);
END IF;

  FOR REC IN (
    SELECT  X.DID_PATTERN, X.STATUS, X.ERROR, X.SYSTEMNAME
    FROM JSON_TABLE(VV_HTTP_RESPONSE, '$'
    COLUMNS(
      STATUS VARCHAR(50) PATH '$.status',
      ERROR VARCHAR(50) PATH '$.error',
      NESTED PATH '$.tenants[*]'
      COLUMNS ( 
      SYSTEMNAME VARCHAR2(100) PATH '$.system_name',
      NESTED PATH '$.did_patterns[*]'
      COLUMNS (
      DID_PATTERN VARCHAR2(200) PATH '$'))
      ) ) AS X )

Loop  
    IF (REC.STATUS = 'success') THEN 
        IF (REC.SYSTEMNAME = PBX_NUMBER) THEN
        VV_CNT:=VV_CNT+1;
        VO_MESSAGE := REC.STATUS;
        VV_DID := VV_DID ||'<DID>'||regexp_replace(REC.DID_PATTERN,'(.{4})(.*)','\2')||'</DID>';
    END IF;
    ELSE 
        VO_MESSAGE := 'Error: Unable to query tenant';
        VO_RESULT := -4012;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VO_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
END IF;             
End Loop;


  FOR REC IN (
    SELECT X.STATUS, X.ERROR, X.ID, X.NAME, X.SYSTEMNAME, X.MTSTATUS, X.PLAN
    FROM JSON_TABLE(VV_HTTP_RESPONSE, '$'
    COLUMNS(
      STATUS VARCHAR(50) PATH '$.status',
      ERROR VARCHAR(50) PATH '$.error',
      NESTED PATH '$.tenants[*]'
      COLUMNS ( ID VARCHAR2(200) PATH '$.id',
      NAME VARCHAR2(100) PATH '$.name',
      SYSTEMNAME VARCHAR2(100) PATH '$.system_name',
      MTSTATUS VARCHAR2(100) PATH '$.status',
      PLAN VARCHAR2(100) PATH '$.resource_plan')
      ) ) AS X)

Loop  
    IF (REC.STATUS = 'success') THEN 
        IF (REC.NAME = PBX_NUMBER) THEN
        VV_CNT:=VV_CNT+1;
        VO_MESSAGE := REC.STATUS;

        --PLANNAME Call
        VO_GET_RESOURCE_PLAN_RESULT := PCK_PBX.FN_GET_RESOURCE_PLAN_NM (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, REC.PLAN, VO_GET_PLAN_NM, VO_GET_RESOURCE_PLAN_MESSAGE, VO_GET_RESOURCE_PLAN_RESULT);
        VV_TENANTS := VV_TENANTS||'<ID>'||REC.ID||'</ID>'||'<NAME>'||REC.NAME||'</NAME>'||'<STATUS>'||REC.MTSTATUS||'</STATUS>'||'<PLAN>'||VO_GET_PLAN_NM||'</PLAN>'
                  				||'<DIDS>'||VV_DID||'</DIDS>';  
    END IF;
    ELSE  
    VO_MESSAGE := 'Error: Unable to query tenant';
    VO_RESULT := -4012;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VO_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);

    RETURN VO_RESULT;
END IF;                    
End Loop; 

    IF VV_CNT > 0 THEN             
        VO_TENANTS:='<TENANT>'||VV_TENANTS||'</TENANT>'; 
    ELSE 
        VO_MESSAGE:='Error: Tenant not found';
        VO_RESULT:= -2050; 
    RETURN VO_RESULT;
END IF;           
        VO_MESSAGE:='SUCCESS';
        VO_RESULT:=0;      
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,'USER:'||VI_USERNAME||'|'||VO_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;

--GLOBAL EXCEPTION HANDLING
      EXCEPTION WHEN OTHERS THEN
        ROLLBACK;
        VO_RESULT := -8000;
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN VO_RESULT;   

END FN_GET_TENANT;

FUNCTION fn_get_tenant_id (
    vi_username            VARCHAR2,
    vi_password            VARCHAR2,
    vi_ip_info             VARCHAR2,
    vi_t_number            VARCHAR2,
    vo_tenants_id          OUT  VARCHAR2,
    vo_tenant_resource_id  OUT  VARCHAR2,
    vo_message             OUT  VARCHAR2,
    vo_result              OUT  NUMBER
) RETURN NUMBER AS

 --FUNCTION VARIABLES
    vv_http_url                  VARCHAR2(2000);
    vv_http_parameter            VARCHAR2(2000);
    vv_cnt                       NUMBER := 0;
    vv_tenants                   VARCHAR2(1000);
    vv_http_status               VARCHAR2(100);
    vv_http_response             VARCHAR2(30000);
    pbx_number                   VARCHAR2(200) := 'PBX-' || vi_t_number;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
    vv_mid_id_user               NUMBER := 1;
    vv_log_message               VARCHAR2(3000);
    vv_exe_time                  NUMBER := dbms_utility.get_time;
    vv_sid                       NUMBER;
    vv_do_log                    CHAR;
    vv_name_interface            VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface              NUMBER;
    vv_id_codsystem              NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    http_status                  VARCHAR2(3);
    http_url                     VARCHAR(1000);
    http_parameter               VARCHAR2(1000);
    http_response                VARCHAR2(12000);
    vo_post_auth_tenant_token    VARCHAR2(1000);
    vo_post_auth_tenant_message  VARCHAR2(1000);
    vo_post_auth_tenant_result   INT;
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vv_log_message := vi_ip_info;
    --END INTERFACE DATA


    IF vi_t_number IS NULL OR length(trim(vi_t_number)) = 0 THEN
        vo_message := 'Error: Trunk is missing';
        vo_result := -2000;
        RETURN vo_result;
    END IF;

    vo_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vo_post_auth_tenant_token,
                                                                     vo_post_auth_tenant_message,
                                                                     vo_post_auth_tenant_result);

--    dbms_output.put_line(vo_post_auth_tenant_token);

    IF ( vo_post_auth_tenant_result = 0 ) THEN
        http_url := pck_pbx.gv_http_tenant_url;
        http_parameter := '{"action":"tenants",'
                          || '"token":"'
                          || vo_post_auth_tenant_token
                          || '"}';
        midware.test_http_post(http_url, http_parameter, vv_http_status, vv_http_response);
    END IF;

--    dbms_output.put_line(vv_http_status);

    FOR rec IN (
        SELECT
            x.status,
            x.error,
            x.id,
            x.name,
            x.plan,
            x.did_pattern
        FROM
                JSON_TABLE ( vv_http_response, '$'
                    COLUMNS (
                        status VARCHAR ( 50 ) PATH '$.status',
                        error VARCHAR ( 50 ) PATH '$.error',
                        NESTED PATH '$.tenants[*]'
                            COLUMNS (
                                id VARCHAR2 ( 200 ) PATH '$.id',
                                name VARCHAR2 ( 100 ) PATH '$.name',
                                systemname VARCHAR2 ( 100 ) PATH '$.name',
                                plan VARCHAR2 ( 100 ) PATH '$.resource_plan',
                                did_pattern VARCHAR2 ( 200 ) PATH '$.did_patterns[*]'
                            )
                    )
                )
            AS x
        WHERE
            x.name = pbx_number
    ) LOOP 
--            dbms_output.put_line(rec.status);
        IF rec.status != 'success' THEN
            vo_message := 'Error: Unable to query tenant';
            vo_result := -4012;
            pck_middle.mid_log_execution(vv_sid, sysdate, vo_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_tenants := rec.id;
        vo_tenant_resource_id := rec.plan;
        vv_cnt := vv_cnt + 1;
    END LOOP;

    IF vv_cnt > 0 THEN
        vo_tenants_id := vv_tenants;
    ELSE
        vo_message := 'Error: Tenant not found';
        vo_result := -2050;
--        vo_message := 'status:error, Invalid plan selected.';
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
        RETURN vo_result;
    END IF;

    vo_message := 'SUCCESS';
    vo_result := 0;
    pck_middle.mid_log_execution(vv_sid, sysdate, 'USER:'
                                                  || vi_username
                                                  || '|'
                                                  || vo_message, vv_id_interface, vv_id_codsystem,
                                vv_mid_id_user,
                                vv_exe_time);

    RETURN vo_result;

--Global exception handling
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        vo_result := -8000;
        vo_message := 'ERROR:'
                          || vv_log_message
                          || '|'
                          || sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        RETURN vo_result;
END fn_get_tenant_id;

FUNCTION fn_add_did
(
    vi_username    VARCHAR2,
    vi_password    VARCHAR2,
    vi_ip_info     VARCHAR2,
    vi_t_username  VARCHAR2,
    vi_did_number  VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER

) RETURN NUMBER IS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    http_status                     VARCHAR2(3);
    http_url                        VARCHAR(1000);
    HTTP_PARAMETER                  VARCHAR2(1000);
    HTTP_RESPONSE                   VARCHAR2(12000);
    json_get_did_routes             VARCHAR2(1000);
    json_parameter_update_did_route VARCHAR2(1000);
    VV_POST_AUTH_TENANT_TOKEN       VARCHAR2(1000);
    VV_POST_AUTH_TENANT_MESSAGE     VARCHAR2(1000);
    VV_POST_AUTH_TENANT_RESULT      INT;
    vv_tenant_id_result             NUMBER;
    vv_tenant_id_message            VARCHAR2(100);
    vv_tenant_id                    VARCHAR2(100);
    vv_d_username                   VARCHAR2(100) := '+501'||vi_did_number;
    vv_tenant_resource_id           VARCHAR2(100);

--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA

    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;

--END INTERFACE DATA


    VV_POST_AUTH_TENANT_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VV_POST_AUTH_TENANT_TOKEN, VV_POST_AUTH_TENANT_MESSAGE, VV_POST_AUTH_TENANT_RESULT);

    IF ( VV_POST_AUTH_TENANT_RESULT < 0 ) THEN
        vo_result := VV_POST_AUTH_TENANT_RESULT;
        vo_message := VV_POST_AUTH_TENANT_MESSAGE;

        RETURN vo_result;
    END IF;

    vv_tenant_id_result := pck_pbx.FN_GET_TENANT_ID(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id, vv_tenant_id_message, vv_tenant_id_result);

    IF ( vv_tenant_id_result < 0 ) THEN
        vo_result := vv_tenant_id_result;
        vo_message := vv_tenant_id_message;

                        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_did_number
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

        RETURN vo_result;
    END IF;

    json_get_did_routes := '
        {
            "action":"did-routes",
            "token":"'||VV_POST_AUTH_TENANT_TOKEN||'"
        }
    ';

    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,json_get_did_routes, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);

    IF ( instr(http_response, 'success') < 1 ) THEN
        vo_result := -4012;
        vo_message := 'Error: Unable to query tenant';
                dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_did_number
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    json_parameter_update_did_route := '
    {
        "action":"update-did-routes",
        "token":"'||VV_POST_AUTH_TENANT_TOKEN||'",
        "did-routes": 
        [
    ';

    IF ( instr(http_response, '"did-routes":[]') > 0 ) THEN

        json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||vv_tenant_id||'"'||',"pattern":"'||vv_d_username||'"}]}');

    ELSE

        FOR rec IN (select x.* from JSON_TABLE(http_response, '$' COLUMNS(
        NESTED PATH '$."did-routes"[*]'
            COLUMNS(uuid VARCHAR2(100) PATH '$.uuid', patterns VARCHAR2(100) PATH '$.pattern')
    )) x) LOOP
        IF (rec.patterns = vv_d_username) THEN
            vo_result := -4013;
            vo_message := 'Error: DID route already exists';
            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);
            dbms_output.put_line(to_char($$plsql_line)
                                     || ': '
                                     || vi_username
                                     || '|'
                                     || vi_password
                                     || '|'
                                     || vi_ip_info
                                     || '|'
                                     || vi_t_username
                                     || '|'
                                     || vi_did_number
                                     || '|'
                                     || vo_message
                                     || '|'
                                     || vo_result);
            return vo_result;
        END IF;
        json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||rec.uuid||'"' || ', "pattern":' ||'"'||rec.patterns||'"'||'},');
    END LOOP;

    json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||vv_tenant_id||'"'||',"pattern":"'||vv_d_username||'"}]}');

    END IF;

    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,json_parameter_update_did_route, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);

    IF ( instr(http_response, 'success') < 1 ) THEN
        vo_result := -4014;
        vo_message := 'Error: Unable to update DID route';
        dbms_output.put_line(to_char($$plsql_line)
                                     || ': '
                                     || vi_username
                                     || '|'
                                     || vi_password
                                     || '|'
                                     || vi_ip_info
                                     || '|'
                                     || vi_t_username
                                     || '|'
                                     || vi_did_number
                                     || '|'
                                     || vo_message
                                     || '|'
                                     || vo_result);
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vo_message := 'success';
    vo_result := 0;
        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vi_did_number
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
    RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message,
                                        vv_id_interface,
                                        vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                    dbms_utility.format_error_stack,
                                    dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call
    RETURN vo_result;

END fn_add_did;

FUNCTION FN_GET_RESOURCE_PLAN_ID (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_PLAN_NAME VARCHAR2, VO_RESOURCE_PLAN_ID OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
RETURN NUMBER AS
    --INTERFACE VARIABLES
        VV_MID_ID_USER NUMBER := 1; 
        VV_LOG_MESSAGE VARCHAR2(2000);
        VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
        VV_SID NUMBER;
        VV_DO_LOG CHAR; 
        VV_NAME_INTERFACE VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
        VV_ID_INTERFACE NUMBER;
        VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        VV_HTTP_URL         VARCHAR2(1000);
        VV_HTTP_PARAMETER   VARCHAR2(1000);
        VV_HTTP_STATUS      VARCHAR2(50);
        VV_HTTP_RESPONSE    VARCHAR2(32767);
        VV_PLAN_NAME        VARCHAR2(50);
        VV_RESOURCE_PLAN_ID VARCHAR2(50);
        VV_MESSAGE          VARCHAR(1000);
        vv_cnt              NUMBER(5, 0) := 0;

        --AUTHENTICATION VARIABLES
        AUTH_TOKEN          VARCHAR2(1000);
        AUTH_MESSAGE        VARCHAR2(1000);
        AUTH_RESULT         NUMBER;
        --END AUTHENTICATION VARIABLES
    --END FUNCTION VARIABLES
BEGIN
    --INTERFACE DATA
        SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
        SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
        SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
        VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

        IF (VV_MID_ID_USER < 0) THEN
          VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
          PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
          RETURN VO_RESULT;
        END IF;
        VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA

    AUTH_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT ('AIRVANTAGE', 'TEST', 'VI_IP_INFO', AUTH_TOKEN, AUTH_MESSAGE, AUTH_RESULT);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||'AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);    

    IF (AUTH_RESULT = 0) THEN
        VV_HTTP_URL      :=PCK_PBX.GV_HTTP_TENANT_URL;
        VV_HTTP_PARAMETER:= '{"action":"resource-plans",'||'"token":"'||AUTH_TOKEN||'"}';
        MIDWARE.MID_HTTP_POST(VV_HTTP_URL ,VV_HTTP_PARAMETER, 'application/json',VV_HTTP_STATUS, VV_HTTP_RESPONSE);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_RESPONSE||'|'||VV_HTTP_STATUS);

        FOR REC IN (
            SELECT X.STATUS, X.ERROR, X.id, X.name
            FROM JSON_TABLE(VV_HTTP_RESPONSE, '$'
            COLUMNS(
              STATUS VARCHAR(50) PATH '$.status',
              ERROR VARCHAR(50) PATH '$.error',
              NESTED PATH '$.resource_plans[*]'
              COLUMNS ( ID VARCHAR2(200) PATH '$.id',
              NAME VARCHAR2(100) PATH '$.name')
              ) ) AS X )
        loop     
        IF (rec.status = 'success') THEN
            if (VI_PLAN_NAME = rec.name) then
                VO_RESOURCE_PLAN_ID:= rec.id;
                --VO_PLAN_NAME:= rec.name;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_PLAN_NAME||'|'||VO_RESOURCE_PLAN_ID);
                VV_CNT:=VV_CNT+1;
                VO_RESULT:= 0;
                VO_MESSAGE := 'Successfully retrieved resource plan ID.';
                exit;
            else
               VO_RESULT:= -2050;
               VO_MESSAGE := 'Error: Plan does not exist'; 
            end if;
        else
            VO_MESSAGE := 'Error: Unable to query plan';
            VO_RESULT := -4015;
          PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VO_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
          RETURN VO_RESULT;
        end if;
        end loop;
    END IF;
     VO_RESULT:=0;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
    EXCEPTION 
    WHEN OTHERS
    THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN VO_RESULT;
END FN_GET_RESOURCE_PLAN_ID;

FUNCTION FN_GET_RESOURCE_PLAN_NM (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_RESOURCE_PLAN_ID VARCHAR2, VO_PLAN_NM OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
RETURN NUMBER AS
    --INTERFACE VARIABLES
        VV_MID_ID_USER NUMBER := 1; 
        VV_LOG_MESSAGE VARCHAR2(2000);
        VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
        VV_SID NUMBER;
        VV_DO_LOG CHAR; 
        VV_NAME_INTERFACE VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
        VV_ID_INTERFACE NUMBER;
        VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        VV_HTTP_URL         VARCHAR2(1000);
        VV_HTTP_PARAMETER   VARCHAR2(1000);
        VV_HTTP_STATUS      VARCHAR2(50);
        VV_HTTP_RESPONSE    VARCHAR2(32767);
        VV_PLAN_NAME        VARCHAR2(50);
        VV_RESOURCE_PLAN_ID VARCHAR2(50);
        VV_MESSAGE          VARCHAR(1000);
        vv_cnt              NUMBER(5, 0) := 0;

        --AUTHENTICATION VARIABLES
        AUTH_TOKEN          VARCHAR2(1000);
        AUTH_MESSAGE        VARCHAR2(1000);
        AUTH_RESULT         NUMBER;
        --END AUTHENTICATION VARIABLES
    --END FUNCTION VARIABLES
BEGIN
    --INTERFACE DATA
        SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
        SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
        SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
        VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

        IF (VV_MID_ID_USER < 0) THEN
          VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
          PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
          RETURN VO_RESULT;
        END IF;
        VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA

    AUTH_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT ('AIRVANTAGE', 'TEST', 'VI_IP_INFO', AUTH_TOKEN, AUTH_MESSAGE, AUTH_RESULT);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||'AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);    

    IF (AUTH_RESULT = 0) THEN
        VV_HTTP_URL      :=PCK_PBX.GV_HTTP_TENANT_URL;
        VV_HTTP_PARAMETER:= '{"action":"resource-plans",'||'"token":"'||AUTH_TOKEN||'"}';
        MIDWARE.MID_HTTP_POST(VV_HTTP_URL ,VV_HTTP_PARAMETER, 'application/json',VV_HTTP_STATUS, VV_HTTP_RESPONSE);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_RESPONSE||'|'||VV_HTTP_STATUS);

        FOR REC IN (
            SELECT X.STATUS, X.ERROR, X.id, X.name
            FROM JSON_TABLE(VV_HTTP_RESPONSE, '$'
            COLUMNS(
              STATUS VARCHAR(50) PATH '$.status',
              ERROR VARCHAR(50) PATH '$.error',
              NESTED PATH '$.resource_plans[*]'
              COLUMNS ( ID VARCHAR2(200) PATH '$.id',
              NAME VARCHAR2(100) PATH '$.name')
              ) ) AS X )
        loop     
        IF (REC.STATUS = 'success') THEN
            if (rec.id = VI_RESOURCE_PLAN_ID) then
                VO_PLAN_NM:= rec.name;
                --VO_PLAN_NAME:= rec.name;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_PLAN_NAME||'|'||VO_RESOURCE_PLAN_ID);
                VV_CNT:=VV_CNT+1;
                VO_RESULT:= 0;
                VO_MESSAGE := 'Successfully retrieved plan name'; 
            else
                VO_RESULT:= -2050;
                VO_MESSAGE := 'Error: Plan does not exist'; 
            end if;
        else
            VO_MESSAGE := 'Error: Unable to query plan';
            VO_RESULT := -4015;
          PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VO_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
          RETURN VO_RESULT;
        end if;
        end loop;
    END IF;
     VO_RESULT:=0;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
    EXCEPTION 
    WHEN OTHERS
    THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN VO_RESULT;
END FN_GET_RESOURCE_PLAN_NM;

FUNCTION FN_UPDATE_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VI_PLAN_NAME VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER AS

    --INTERFACE VARIABLES
    VV_MID_ID_USER NUMBER := 1; 
    VV_LOG_MESSAGE VARCHAR2(2000);
    VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID NUMBER;
    VV_DO_LOG CHAR; 
    VV_NAME_INTERFACE VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE NUMBER;
    VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        VV_HTTP_URL             VARCHAR2(2000);
        VV_HTTP_PARAMETER       VARCHAR2(2000);
        VV_HTTP_STATUS          VARCHAR2(100);
        VV_HTTP_RESPONSE        VARCHAR2(32767);
        VV_TENANT_RESOURCE_ID   VARCHAR2(2000);
        VV_MESSAGE              VARCHAR2(2000);
        VV_PLAN_NAME            VARCHAR2(50);

        --FUNCTION VARIABLES
        --AUTHENTICATION VARIABLES
        AUTH_TOKEN              VARCHAR2(1000);
        AUTH_MESSAGE            VARCHAR2(1000);
        AUTH_RESULT             NUMBER;
        --END AUTHENTICATION VARIABLES

        --FIND VARIABLES
        FIND_TENANT_ID          VARCHAR2(1000);
        FIND_MESSAGE            VARCHAR2(1000);
        FIND_TENANT_RESOURCE_ID VARCHAR2(1000);
        FIND_RESULT             NUMBER;
        FIND_HTTP_RESPONSE      VARCHAR2(10000);
        FIND_HTTP_PARAMETER     VARCHAR2(1000);
        FIND_HTTP_STATUS          VARCHAR2(100);
        --END FIND VARIABLES

         --RESOURCE VARIABLES
        RES_MESSAGE            VARCHAR2(1000);
        RES_RESOURCE_PLAN_ID VARCHAR2(1000);
        RES_RESULT             NUMBER;        
        --END RESOURCE VARIABLES

    --END FUNCTION VARIABLES

BEGIN
    VV_PLAN_NAME := UPPER(VI_PLAN_NAME);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_PLAN_NAME);    
    --INTERFACE DATA
    SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
    SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
    SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF (VV_MID_ID_USER < 0) THEN
      VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
      PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
      RETURN VO_RESULT;
    END IF;
    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA
    /*
    IF REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$') AND (REGEXP_LIKE(VI_T_NEW_USERNAME,'^[0-9]{7}$') OR VI_T_NEW_USERNAME IS NULL) THEN
    */
    IF REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$') and (VI_T_NEW_USERNAME IS null or VI_T_NEW_USERNAME IS not null and REGEXP_LIKE(VI_T_NEW_USERNAME,'^[0-9]{7}$')) THEN

    AUTH_RESULT:= PCK_PBX.FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, AUTH_TOKEN, AUTH_MESSAGE, AUTH_RESULT);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||AUTH_RESULT||'|'||AUTH_TOKEN||'|'||AUTH_MESSAGE);

    FIND_RESULT:= PCK_PBX.FN_GET_TENANT_ID (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, FIND_TENANT_ID, FIND_TENANT_RESOURCE_ID, FIND_MESSAGE, FIND_RESULT);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_RESULT||'|'||FIND_TENANT_RESOURCE_ID||'|'||FIND_MESSAGE);

    RES_RESULT:= PCK_PBX.FN_GET_RESOURCE_PLAN_ID (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VV_PLAN_NAME, RES_RESOURCE_PLAN_ID, RES_MESSAGE, RES_RESULT);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESULT||'|'||RES_RESOURCE_PLAN_ID||'|'||RES_MESSAGE);

    --VV_HTTP_PARAMETER:= '{"action":"resource-plans",'||'"token":"'||AUTH_TOKEN||'"}';
    FIND_HTTP_PARAMETER:='{"action":"tenant", "id":"'||FIND_TENANT_ID||'",'||'"token":"'||AUTH_TOKEN||'"}';
    MIDWARE.MID_HTTP_POST(PCK_PBX.GV_HTTP_TENANT_URL ,FIND_HTTP_PARAMETER, 'application/json', FIND_HTTP_STATUS, FIND_HTTP_RESPONSE);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_HTTP_STATUS||'|'||FIND_HTTP_RESPONSE);

    SELECT json_value(FIND_HTTP_RESPONSE, '$.status') into FIND_HTTP_STATUS FROM dual;
    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'FIND_HTTP_STATUS='||FIND_HTTP_STATUS);
    If FIND_HTTP_STATUS = 'success' THEN

        IF (VV_PLAN_NAME IS NULL) THEN
            VV_TENANT_RESOURCE_ID:= FIND_TENANT_RESOURCE_ID;
        ELSE
            VV_TENANT_RESOURCE_ID:= RES_RESOURCE_PLAN_ID;
        END IF;

        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_TENANT_RESOURCE_ID);
        IF ((VI_T_NEW_USERNAME IS NULL or VI_T_USERNAME = VI_T_NEW_USERNAME) and FIND_TENANT_RESOURCE_ID != RES_RESOURCE_PLAN_ID /*OR VI_PLAN_NAME IS NOT NULL*/) THEN
        --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID);
                FIND_HTTP_RESPONSE:= substr(FIND_HTTP_RESPONSE,INSTR(find_http_response, '"owner"'));
                FIND_HTTP_RESPONSE:= substr(FIND_HTTP_RESPONSE, 1, length(FIND_HTTP_RESPONSE) -1);
            IF (VV_TENANT_RESOURCE_ID IS NOT NULL) THEN
                FIND_HTTP_RESPONSE:= REPLACE(FIND_HTTP_RESPONSE, FIND_TENANT_RESOURCE_ID, VV_TENANT_RESOURCE_ID);
                --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID);

            VV_HTTP_PARAMETER:= '{"action":"update-tenant","id":"'||FIND_TENANT_ID
                                    ||'","token":"'||AUTH_TOKEN||'",'
                                    || FIND_HTTP_RESPONSE;
            --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_PARAMETER);
            VV_HTTP_URL      :=PCK_PBX.GV_HTTP_TENANT_URL;
            MIDWARE.MID_HTTP_POST(VV_HTTP_URL ,VV_HTTP_PARAMETER, 'application/json',VV_HTTP_STATUS, VV_HTTP_RESPONSE);

            SELECT json_value(VV_HTTP_RESPONSE, '$.status') into VV_HTTP_STATUS FROM dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_HTTP_STATUS='||VV_HTTP_STATUS);
            If VV_HTTP_STATUS = 'pending' THEN 
                SELECT 'Tenant is being updated.' into VV_MESSAGE FROM dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);
                VO_MESSAGE := VV_MESSAGE;
                VO_RESULT := 0;
                ELSE 
                SELECT json_value(VV_HTTP_RESPONSE, '$.error') into VV_MESSAGE FROM dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);
                VO_RESULT := -4016;
                VO_MESSAGE := 'Error: Unable to update tenant';
                RETURN VO_RESULT;
            END IF;
            ELSE
                VO_MESSAGE := RES_MESSAGE;
                VO_RESULT := RES_RESULT;
            END IF;
        ELSIF ((VI_T_NEW_USERNAME IS NULL or VI_T_USERNAME = VI_T_NEW_USERNAME) AND (FIND_TENANT_RESOURCE_ID = RES_RESOURCE_PLAN_ID OR VV_PLAN_NAME IS NULL)) THEN
                SELECT 'Error: New username or plan must be entered' into VV_MESSAGE FROM dual;
                VO_MESSAGE := VV_MESSAGE;
                VO_RESULT := -2002;                
        ELSE
                --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID||'|'||VV_TENANT_RESOURCE_ID);
                FIND_HTTP_RESPONSE:= substr(FIND_HTTP_RESPONSE,INSTR(find_http_response, '"owner"'));
                FIND_HTTP_RESPONSE:= substr(FIND_HTTP_RESPONSE, 1, length(FIND_HTTP_RESPONSE) -1);
                IF (VI_T_NEW_USERNAME IS NOT NULL) THEN
                    FIND_HTTP_RESPONSE:= REPLACE(FIND_HTTP_RESPONSE, VI_T_USERNAME, VI_T_NEW_USERNAME);
                END IF;
                IF (VV_TENANT_RESOURCE_ID IS NOT NULL) THEN
                    FIND_HTTP_RESPONSE:= REPLACE(FIND_HTTP_RESPONSE, FIND_TENANT_RESOURCE_ID, VV_TENANT_RESOURCE_ID);

                --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_HTTP_RESPONSE);

                VV_HTTP_PARAMETER:=  '{"action":"update-tenant","id":"'||FIND_TENANT_ID
                                        ||'","token":"'||AUTH_TOKEN||'",'
                                        ||FIND_HTTP_RESPONSE;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_PARAMETER);
                VV_HTTP_URL      :=PCK_PBX.GV_HTTP_TENANT_URL;
                MIDWARE.MID_HTTP_POST(VV_HTTP_URL ,VV_HTTP_PARAMETER, 'application/json',VV_HTTP_STATUS, VV_HTTP_RESPONSE);

                SELECT json_value(VV_HTTP_RESPONSE, '$.status') into VV_HTTP_STATUS FROM dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_HTTP_STATUS='||VV_HTTP_STATUS);
                If VV_HTTP_STATUS = 'pending' THEN 
                    SELECT 'Tenant is being updated.' into VV_MESSAGE FROM dual;
                    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);
                    VO_MESSAGE := VV_MESSAGE;
                    VO_RESULT := 0;
                    ELSE 
                    SELECT json_value(VV_HTTP_RESPONSE, '$.error') into VV_MESSAGE FROM dual;
                    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);
                    VO_RESULT := -4016;
                    VO_MESSAGE := 'Error: Unable to update tenant';
                    RETURN VO_RESULT;
                END IF;
                ELSE
                    VO_MESSAGE := RES_MESSAGE;
                    VO_RESULT := RES_RESULT;
                END IF;
        END IF;        
    ELSE
                VO_RESULT := FIND_RESULT;
                VO_MESSAGE := FIND_MESSAGE;
                RETURN VO_RESULT;
    END IF;
    ELSE
        SELECT 'Error: Trunk must be 7 digit numeric value' into VV_MESSAGE FROM dual;
        VO_MESSAGE := VV_MESSAGE;
        VO_RESULT := -2001;
    END IF;    
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
    EXCEPTION
    WHEN OTHERS
    THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
   RETURN VO_RESULT;
END FN_UPDATE_TENANT;

FUNCTION FN_DELETE_TENANT(VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VO_MESSAGE OUT  VARCHAR2, 
                 VO_RESULT OUT  NUMBER)

RETURN NUMBER IS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    http_status                     VARCHAR2(3);
    http_url                        VARCHAR(1000);
    HTTP_PARAMETER                  VARCHAR2(1000);
    HTTP_RESPONSE                   VARCHAR2(12000);
    json_get_did_routes             VARCHAR2(1000);
   json_parameter_delete_tenant VARCHAR2(1000);
    VV_POST_AUTH_TENANT_TOKEN       VARCHAR2(1000);
    VV_POST_AUTH_TENANT_MESSAGE     VARCHAR2(1000);
    VV_POST_AUTH_TENANT_RESULT      INT;
    vv_tenant_id_result             NUMBER;
    vv_tenant_id_message            VARCHAR2(100);
    vv_tenant_id                    VARCHAR2(100);
    --vv_d_username                   VARCHAR2(100) := '+501'||vi_did_number;
    vv_tenant_resource_id           VARCHAR2(100);

--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;


    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA


  --NUMERIC VALIDATION
  IF NOT regexp_like ( VI_T_USERNAME, '^[0-9]{7}$') THEN
    VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
      VO_RESULT := -2001;
  RETURN VO_RESULT;
END IF;


    VV_POST_AUTH_TENANT_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VV_POST_AUTH_TENANT_TOKEN, VV_POST_AUTH_TENANT_MESSAGE, VV_POST_AUTH_TENANT_RESULT);

    IF ( VV_POST_AUTH_TENANT_RESULT < 0 ) THEN
        vo_result := VV_POST_AUTH_TENANT_RESULT;
        vo_message := VV_POST_AUTH_TENANT_MESSAGE;

        RETURN vo_result;
    END IF;

    vv_tenant_id_result := pck_pbx.FN_GET_TENANT_ID(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id, vv_tenant_id_message, vv_tenant_id_result);


    dbms_output.put_line(vv_tenant_id);    
    IF ( vv_tenant_id_result < 0 ) THEN
        vo_result := vv_tenant_id_result;
        vo_message := vv_tenant_id_message;      

        RETURN vo_result;
    END IF;   


    json_parameter_delete_tenant := '
    {
        "action":"delete-tenant",
        "id":"'||vv_tenant_id||'",
        "token":"'||VV_POST_AUTH_TENANT_TOKEN||'"}';   


    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,json_parameter_delete_tenant, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);

    dbms_output.PUT_LINE(HTTP_RESPONSE);

    IF ( instr(http_response, 'pending') < 1 ) THEN
        vo_result := -4019;
        vo_message := 'Error: Unable to delete tenant';

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,vv_mid_id_user, vv_exe_time);

        RETURN vo_result;
    END IF;

    vo_message := 'success';
    vo_result := 0;       

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,vv_mid_id_user, vv_exe_time);
    RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
    VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN vo_result;

END FN_DELETE_TENANT;

FUNCTION FN_DELETE_DID(VI_USERNAME VARCHAR2,VI_PASSWORD VARCHAR2,VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2,
             VI_DID_NUMBER VARCHAR2, VO_MESSAGE OUT  VARCHAR2,VO_RESULT OUT NUMBER) 
RETURN NUMBER IS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    http_status                     VARCHAR2(3);
    http_url                        VARCHAR(1000);
    HTTP_PARAMETER                  VARCHAR2(1000);
    HTTP_RESPONSE                   VARCHAR2(12000);
    json_get_did_routes             VARCHAR2(1000);
    json_parameter_update_did_route VARCHAR2(1000);
    VV_POST_AUTH_TENANT_TOKEN       VARCHAR2(1000);
    VV_POST_AUTH_TENANT_MESSAGE     VARCHAR2(1000);
    VV_POST_AUTH_TENANT_RESULT      INT;
    vv_tenant_id_result             NUMBER;
    vv_tenant_id_message            VARCHAR2(100);
    vv_tenant_id                    VARCHAR2(100);
    vv_d_username                   VARCHAR2(100) := '+501'||vi_did_number;
    vv_tenant_resource_id           VARCHAR2(100);
    vv_did_found          INT;
    vv_count            INT;

--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA

    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;

--END INTERFACE DATA

  vv_did_found:=0;
  vv_count:=0;

    VV_POST_AUTH_TENANT_RESULT := PCK_PBX.FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VV_POST_AUTH_TENANT_TOKEN, VV_POST_AUTH_TENANT_MESSAGE, VV_POST_AUTH_TENANT_RESULT);

    IF ( VV_POST_AUTH_TENANT_RESULT < 0 ) THEN
        vo_result := VV_POST_AUTH_TENANT_RESULT;
        vo_message := VV_POST_AUTH_TENANT_MESSAGE;

        RETURN vo_result;
    END IF;

    vv_tenant_id_result := pck_pbx.FN_GET_TENANT_ID(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id, vv_tenant_id_message, vv_tenant_id_result);

    IF ( vv_tenant_id_result < 0 ) THEN
        vo_result := vv_tenant_id_result;
        vo_message := vv_tenant_id_message;        
        RETURN vo_result;
    END IF;

    json_get_did_routes := '
        {
            "action":"did-routes",
            "token":"'||VV_POST_AUTH_TENANT_TOKEN||'"
        }
    ';

    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,json_get_did_routes, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);

    IF ( instr(http_response, 'success') < 1 ) THEN
        vo_result := -4017;
        vo_message := 'Error: Unable to query DID routes';

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    json_parameter_update_did_route := '
    {
        "action":"update-did-routes",
        "token":"'||VV_POST_AUTH_TENANT_TOKEN||'",
        "did-routes": 
        [
    ';

    /*
    IF ( instr(http_response, '"did-routes":[]') > 0 ) THEN

        json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||vv_tenant_id||'"'||',"pattern":"'||vv_d_username||'"}]}');

    ELSE*/

    FOR rec IN (select x.* 
            from JSON_TABLE(http_response,'$' 
                         COLUMNS(NESTED PATH '$."did-routes"[*]'
                             COLUMNS(uuid VARCHAR2(100) PATH '$.uuid', 
                                       patterns VARCHAR2(100) PATH '$.pattern') )
                  ) x
         ) 
    LOOP

        IF (rec.patterns = vv_d_username) THEN 
          vv_did_found:=1;
        ELSE 
                --json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||rec.uuid||'"' || ', "pattern":' ||'"'||rec.patterns||'"'||'},');
                IF vv_count= 0 THEN 
                  json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||rec.uuid||'"' || ', "pattern":' ||'"'||rec.patterns||'"'||'}');
                ELSE 
                  json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, ',{"uuid":'||'"'||rec.uuid||'"' || ', "pattern":' ||'"'||rec.patterns||'"'||'}');
                END IF;   
        END IF;

        vv_count:=vv_count+1;

    END LOOP;

    json_parameter_update_did_route := CONCAT(json_parameter_update_did_route,']}');

    IF vv_did_found != 1 THEN 
      vo_result:= -2050;
      vo_message:= 'Error: DID route not found';

      pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,vv_mid_id_user,vv_exe_time);
      RETURN vo_result;

    END IF;    

    MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,json_parameter_update_did_route, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);
    dbms_output.PUT_LINE(json_parameter_update_did_route);

    IF ( instr(http_response, 'success') < 1 ) THEN
        vo_result := -4018;
        vo_message := 'Error: Unable to delete DID route';

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,vv_mid_id_user,vv_exe_time);

        RETURN vo_result;
    END IF;

    vo_message := 'success';
    vo_result := 0;       

    pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user,vv_exe_time);
    RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN vo_result;

END FN_DELETE_DID;

FUNCTION fn_find_trunk (
    vi_username    VARCHAR2,
    vi_password    VARCHAR2,
    vi_ip_info     VARCHAR2,
    vi_t_username  VARCHAR2,
    vi_product     VARCHAR2,
    vo_trunk_id    OUT  NUMBER,
    vo_t_username  OUT  VARCHAR2,
    vo_t_password  OUT  VARCHAR2,
    vo_result      OUT  NUMBER,
    vo_message     OUT  VARCHAR2
) RETURN NUMBER AS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES

    http_status           VARCHAR2(3);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
    http_url_authenticate VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --http_url_find_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/find_trunk';
    http_url_find_trunk   VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/find_trunk';
    http_url              VARCHAR(1000);
    http_parameter        VARCHAR2(1000);
    http_response         VARCHAR2(12000);
    vo_post_auth_result   INT;
    vo_post_auth_message  VARCHAR2(1000);
    vo_post_auth_token    VARCHAR2(1000);
    vv_trunk_id           NUMBER;
    vv_t_username         VARCHAR2(25);

BEGIN

vo_trunk_id := 0;

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vv_log_message := vi_ip_info;
--END INTERFACE DATA

    vo_post_auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username,
                                                       vo_post_auth_message,
                                                       vo_post_auth_token,
                                                       vo_post_auth_result);

--    dbms_output.put_line(vo_post_auth_result);

    IF ( vo_post_auth_result = 0 ) THEN
        http_parameter := 'token='
                          || vo_post_auth_message
                          || '&outgoing_username=%2B501'
                          || vi_t_username;
        midware.test_http_post(http_url_find_trunk, http_parameter, http_status, http_response);

        IF ( instr(http_response, vi_t_username) >= 1 ) THEN
            vo_result := 0;
            vo_message := 'success';
            SELECT json_value(HTTP_RESPONSE, '$.data.trunk_id') into vo_trunk_id FROM dual;
            SELECT json_value(HTTP_RESPONSE, '$.data.outgoing_username') into vo_t_username FROM dual;
            SELECT json_value(HTTP_RESPONSE, '$.data.outgoing_remotesecret') into vo_t_password FROM dual;
            vo_t_username := LTRIM (vo_t_username, '+501');

            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_trunk_id
                                 || '|'
                                 || vo_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        ELSIF ( instr(http_response, '"data":[]') >= 1 ) THEN
        -- "data":[]
            vo_result := -2050;
            vo_message := 'Error: Trunk not found';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_trunk_id
                                 || '|'
                                 || vo_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result); 

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        ELSE
            vo_result := -5011;
            vo_message := 'Error: Unable to query trunk';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        END IF;

    END IF;

    vo_result := -5000;
    vo_message := 'Error: Tenant Authentication Unsuccessful';
    dbms_output.put_line(to_char($$plsql_line)
                         || ': '
                         || vi_username
                         || '|'
                         || vi_password
                         || '|'
                         || vi_ip_info
                         || '|'
                         || vi_t_username
                         || '|'
                         || vo_message
                         || '|'
                         || vo_result);

    pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                vv_mid_id_user,
                                vv_exe_time);

    RETURN vo_result;

    --When any errors then it logs the error
EXCEPTION
    WHEN OTHERS THEN
        vo_result := -8000;
        vo_message := sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                      || vi_ip_info
                                                      || ':'
                                                      || vo_message,
                                    vv_id_interface,
                                    vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        dbms_output.put_line(to_char($$plsql_line)
                             || ': '
                             || dbms_utility.format_error_stack
                             || dbms_utility.format_call_stack
                             || dbms_utility.format_error_backtrace); --TO DO: Log error with session call
        RETURN vo_result;
END fn_find_trunk;

FUNCTION FN_UPDATE_SUBSCRIBER (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VI_T_NEW_PASSWORD VARCHAR2, VI_PRODUCT IN VARCHAR2, VO_RESULT OUT NUMBER, VO_MESSAGE OUT VARCHAR2)
    RETURN NUMBER AS
    --INTERFACE VARIABLES
    VV_MID_ID_USER NUMBER := 1; 
    VV_LOG_MESSAGE VARCHAR2(2000);
    VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID NUMBER;
    VV_DO_LOG CHAR; 
    VV_NAME_INTERFACE VARCHAR2(24) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE NUMBER;
    VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        VV_MESSAGE            VARCHAR2(1000);
        --AUTHENTICATION VARIABLES
        AUTH_HTTP_URL         VARCHAR2(2000);
        AUTH_HTTP_PARAMETER   VARCHAR2(2000);
        AUTH_TOKEN            VARCHAR2(1000);
        AUTH_MESSAGE          VARCHAR2(1000);
        AUTH_RESULT           NUMBER;
        --FIND_TRUNK VARIABLES
        FIND_HTTP_URL         VARCHAR2(2000);
        FIND_HTTP_PARAMETER   VARCHAR2(2000);
        FIND_HTTP_MESSAGE     VARCHAR2(2000);
        FIND_RESULT           NUMBER;
        FIND_TRUNK_ID         NUMBER;
        FIND_T_USERNAME       VARCHAR2(100);
        FIND_PRODUCT          VARCHAR2(100);
        --UPDATE_TRUNK VARIABLES
        UPD_HTTP_URL         VARCHAR2(2000);
        UPD_HTTP_PARAMETER   VARCHAR2(2000);
        UPD_HTTP_RESPONSE    VARCHAR2(2000);
        UPD_MESSAGE          VARCHAR2(1000);
        UPD_RESULT           VARCHAR2(1000);
        UPD_STATUS           VARCHAR2(1000);
        --UPDATE_U2000 VARIABLES
        UPD_U2000_RESULT            NUMBER;
        UPD_U2000_MESSAGE    VARCHAR2(1000);    
        FIND_T_PASSWORD      VARCHAR2(100);

    --END FUNCTION VARIABLES
    gv_codsystem VARCHAR2(20) := 'HOSTED';
BEGIN
    --INTERFACE DATA
    SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
    SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
    SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF (VV_MID_ID_USER < 0) THEN
      VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
      PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
      RETURN VO_RESULT;
    END IF;
    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA
    IF REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$') and (VI_T_NEW_USERNAME IS null or VI_T_NEW_USERNAME IS not null and REGEXP_LIKE(VI_T_NEW_USERNAME,'^[0-9]{7}$')) THEN
    VO_MESSAGE:= null;
    --AUTH_HTTP_URL      :=VI_TENANT_URL;
    --AUTH_HTTP_PARAMETER:=VI_API_KEY;
    AUTH_RESULT        := PCK_PBX.FN_POST_AUTHENTICATE(VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, AUTH_TOKEN, AUTH_MESSAGE, AUTH_RESULT);
    --dbms_output.PUT_LINE('AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);
    VO_MESSAGE:= AUTH_MESSAGE;

    FIND_RESULT:=   PCK_PBX.FN_FIND_TRUNK (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, FIND_PRODUCT, FIND_TRUNK_ID, FIND_T_USERNAME, FIND_T_PASSWORD, FIND_RESULT, FIND_HTTP_MESSAGE);
    --dbms_output.PUT_LINE('FIND_TRUNK_ID='||FIND_TRUNK_ID||'|'||'FIND_HTTP_MESSAGE='||FIND_HTTP_MESSAGE);
    VO_MESSAGE:= FIND_HTTP_MESSAGE;
    IF (FIND_TRUNK_ID >= 1) THEN
        VO_RESULT:=0;

        IF ((VI_T_NEW_USERNAME IS NULL or VI_T_USERNAME = VI_T_NEW_USERNAME) and VI_T_NEW_PASSWORD is not null) THEN        

            UPD_HTTP_PARAMETER:=  'token=' ||AUTH_TOKEN     
                              || '&outgoing_remotesecret='|| VI_T_NEW_PASSWORD
                              || '&register=%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'---mtob-'||GV_OUTBOUND_PROXY||'%3A'||VI_T_NEW_PASSWORD||'%3A%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'%40'||GV_OUTBOUND_PROXY||'%3A'||GV_OUTGOING_PORT||'%2F%2B501'||VI_T_USERNAME
                              ;

        ELSIF (VI_T_USERNAME != VI_T_NEW_USERNAME) then
            IF VI_T_NEW_PASSWORD IS NULL THEN
                UPD_HTTP_PARAMETER:=  'token='|| AUTH_TOKEN
                                || '&description=%2B501' ||VI_T_NEW_USERNAME
                                || '&outgoing_username=%2B501' ||VI_T_NEW_USERNAME
                                || '&outgoing_defaultuser=%2B501' ||VI_T_NEW_USERNAME                            
                                || '&outgoing_fromuser=%2B501' ||VI_T_NEW_USERNAME
                                || '&trunk_cid=%22%22%20%3C%2B501' ||VI_T_NEW_USERNAME||'%3E'
								|| '&outgoing_remotesecret=' ||FIND_T_PASSWORD
								|| '&register=%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'---mtob-'||GV_OUTBOUND_PROXY||'%3A'||FIND_T_PASSWORD||'%3A%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'%40'||GV_OUTBOUND_PROXY||'%3A'||GV_OUTGOING_PORT||'%2F%2B501'||VI_T_NEW_USERNAME
                                ;
            ELSE
                UPD_HTTP_PARAMETER:=  'token='|| AUTH_TOKEN
                                || '&description=%2B501' ||VI_T_NEW_USERNAME
                                || '&outgoing_username=%2B501' ||VI_T_NEW_USERNAME
                                || '&outgoing_defaultuser=%2B501' ||VI_T_NEW_USERNAME                            
                                || '&outgoing_fromuser=%2B501' ||VI_T_NEW_USERNAME
                                || '&outgoing_remotesecret=' ||VI_T_NEW_PASSWORD
                                || '&trunk_cid=%22%22%20%3C%2B501' ||VI_T_NEW_USERNAME||'%3E'
								|| '&register=%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'---mtob-'||GV_OUTBOUND_PROXY||'%3A'||VI_T_NEW_PASSWORD||'%3A%2B501'||VI_T_NEW_USERNAME||'%40'||GV_OUTGOING_HOST||'%40'||GV_OUTBOUND_PROXY||'%3A'||GV_OUTGOING_PORT||'%2F%2B501'||VI_T_NEW_USERNAME
                                ;
            END IF;
        ELSE
            RETURN 0;
        END IF;
        UPD_HTTP_URL:= 'https://'||'PBX-'||vi_t_username||'.'||PCK_PBX.GV_HTTP_URL||'/modify_trunk/'||FIND_TRUNK_ID;
        MIDWARE.TEST_HTTP_POST(UPD_HTTP_URL, UPD_HTTP_PARAMETER, UPD_RESULT, UPD_HTTP_RESPONSE);

        SELECT json_value(UPD_HTTP_RESPONSE, '$.status') into UPD_STATUS FROM dual;
        --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_STATUS='||VV_STATUS);
        If UPD_STATUS = 'success' THEN 
            SELECT 'Trunk ID '||FIND_TRUNK_ID||' was succesfully updated.' into UPD_MESSAGE FROM dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_MESSAGE='||UPD_MESSAGE);
            VO_MESSAGE := UPD_MESSAGE;
            ELSE 
            SELECT json_value(UPD_HTTP_RESPONSE, '$.message') into UPD_MESSAGE FROM dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_MESSAGE='||UPD_MESSAGE);
            VO_RESULT := -5012;
            VO_MESSAGE := 'Error: Unable to update trunk';        
            RETURN VO_RESULT;
        END IF;
        --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VO_RESULT='||VO_RESULT);
        IF VO_RESULT = 0 THEN
            UPD_U2000_RESULT:= PCK_PBX.FN_UPDATE_TRUNK_U2000_MIDDB (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VI_T_NEW_USERNAME, UPD_U2000_RESULT, UPD_U2000_MESSAGE);
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_U2000_RESULT='||UPD_U2000_RESULT);
        ELSE
            RETURN 0;
        END IF;
        IF VO_RESULT != UPD_U2000_RESULT THEN
            VO_MESSAGE := 'Partial Success: '||UPD_MESSAGE||' '||UPD_U2000_MESSAGE;
            VO_RESULT := -6000;
        END IF;
    END IF;
ELSE
    SELECT 'USERNAME NEEDS TO BE NUMERIC AND 7 DIGITS LONG.' into VV_MESSAGE FROM dual;
    VO_MESSAGE := VV_MESSAGE;
    VO_RESULT := -1001;
END IF;
    VO_RESULT:=0;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
  EXCEPTION 
   WHEN OTHERS
  THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
   RETURN VO_RESULT;    
END FN_UPDATE_SUBSCRIBER;

FUNCTION FN_UPDATE_TRUNK_U2000_MIDDB (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VO_RESULT OUT NUMBER, VO_MESSAGE OUT VARCHAR2)
    RETURN NUMBER AS

    --INTERFACE VARIABLES
    VV_MID_ID_USER NUMBER := 1; 
    VV_LOG_MESSAGE VARCHAR2(2000);
    VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID NUMBER;
    VV_DO_LOG CHAR; 
    VV_NAME_INTERFACE VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE NUMBER;
    VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES

    UPD_PBX_ID NUMBER;
    GET_RESULT NUMBER;
    GET_MESSAGE VARCHAR2(400);
    UPD_RESULT VARCHAR2(400);
    UPD_TRUNK NUMBER;
    UPD_CDATE VARCHAR2(400);
    CNT NUMBER;

    BEGIN
    --INTERFACE DATA
    SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
    SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
    SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF (VV_MID_ID_USER < 0) THEN
      VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
      PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
      RETURN VO_RESULT;
    END IF;
    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA

    SELECT COUNT(HOSTED.PBX_ID) INTO CNT FROM MIDWARE.HOSTED_PBX_U2000 HOSTED WHERE VI_T_USERNAME= PHONE_NUM AND DELETED_AT IS NULL;
    dbms_output.PUT_LINE(to_char($$plsql_line)||'counter'||'|'||cnt);

    IF CNT >1 THEN
         VO_RESULT:= -2200;
         VO_MESSAGE:= 'Fetch returns more than 1 active instance on the number '||VI_T_USERNAME;
    END IF;

    IF CNT = 1 THEN

        GET_RESULT:= PCK_PBX.fn_get_trunk_u2000(vi_username, vi_password, vi_ip_info, vi_t_username, get_message, get_result);
        --dbms_output.PUT_LINE(to_char($$plsql_line)||'GET_RESULT'||'|'||GET_RESULT);       

        IF GET_RESULT = 0 THEN

            SELECT PBX_ID INTO UPD_PBX_ID FROM MIDWARE.HOSTED_PBX_U2000 where VI_T_USERNAME= PHONE_NUM AND DELETED_AT IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_PBX_ID'||'|'||UPD_PBX_ID);

            SELECT CREATED_AT INTO UPD_CDATE FROM MIDWARE.HOSTED_PBX_U2000 where VI_T_USERNAME= PHONE_NUM AND DELETED_AT IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_CDATE'||'|'||UPD_CDATE);

            SELECT TRUNK_ID INTO UPD_TRUNK FROM MIDWARE.HOSTED_PBX_U2000 where VI_T_USERNAME= PHONE_NUM AND DELETED_AT IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_TRUNK'||'|'||UPD_TRUNK);

            UPD_RESULT := PCK_PBX.FN_SSH_CONNECT(GV_UPDATE_U2000||' '||VI_T_NEW_USERNAME||' '||UPD_TRUNK);
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'|'||UPD_RESULT);

            IF UPD_RESULT = 'SUCCESS' THEN
                UPDATE MIDWARE.HOSTED_PBX_U2000 SET DELETED_AT = SYSDATE WHERE UPD_PBX_ID = PBX_ID;

                INSERT INTO MIDWARE.HOSTED_PBX_U2000(TRUNK_ID, ROUTE_ID, SUB_ROUTE_ID, PHONE_NUM, CREATED_AT, UPDATED_AT, DELETED_AT)
                VALUES (UPD_TRUNK, UPD_TRUNK, UPD_TRUNK, VI_T_NEW_USERNAME, UPD_CDATE, SYSDATE, NULL);
                COMMIT;
            ELSE
                VO_RESULT:= -3000;
                VO_MESSAGE:= UPD_RESULT;
            END IF;
        ELSE
           VO_RESULT:= get_result;
           VO_MESSAGE:= get_message;
        END IF;
        VO_RESULT:=0;
        VO_MESSAGE:= 'The number '||VI_T_USERNAME||' was changed to '||VI_T_NEW_USERNAME||'.';
    ELSIF CNT = 0 THEN
        VO_RESULT:= -2100;
        VO_MESSAGE:= 'The number '||VI_T_USERNAME||' does not exists in HOSTED_PBX_U2000 Table.';
    END IF;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
    EXCEPTION
    WHEN OTHERS
    THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
    RETURN VO_RESULT;
END FN_UPDATE_TRUNK_U2000_MIDDB;

FUNCTION fn_get_trunk_u2000
(
    vi_username    VARCHAR2,
    vi_password    VARCHAR2,
    vi_ip_info     VARCHAR2,
    vi_t_username  VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER

) RETURN NUMBER IS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
    trunk_id                        NUMBER;
    json_get_did_routes             VARCHAR2(1000);
    json_parameter_update_did_route VARCHAR2(1000);
    ssh_message                     VARCHAR2(100);
    ssh_result                      NUMBER;
--END PROGRAM VARIABLES

l_pbx_id INT;
BEGIN

--INTERFACE DATA

    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;

--END INTERFACE DATA

    BEGIN
        SELECT HOSTED.TRUNK_ID  INTO trunk_id FROM MIDWARE.HOSTED_PBX_U2000 HOSTED WHERE HOSTED.PHONE_NUM = vi_t_username AND HOSTED.DELETED_AT IS NULL;        
        EXCEPTION WHEN NO_DATA_FOUND THEN          
            RAISE NO_DATA_FOUND;
            
            dbms_output.PUT_LINE('DEBUG PBX_ID:'||l_pbx_id);
    END;


    ssh_message := PCK_PBX.FN_SSH_CONNECT(GV_GET_U2000
                                        ||' '
                                        ||trunk_id);

    ssh_result := regexp_replace(ssh_message, '[^[:digit:]]', '');


    if (ssh_result > 0) THEN
        vo_message := regexp_replace(ssh_message, '[^a-z and ^A-Z]', '');
        vo_result := ssh_result;
        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution

        RETURN vo_result;
    END IF;

    vo_message := 'success';
    vo_result := 0;
        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution      

    RETURN vo_result;

    --When any errors then it logs the error

    EXCEPTION
        WHEN NO_DATA_FOUND THEN

            vo_result := -2100;
            vo_message := sqlerrm;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message,
                                        vv_id_interface,
                                        vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                    dbms_utility.format_error_stack,
                                    dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

    RETURN vo_result;

        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message,
                                        vv_id_interface,
                                        vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                    dbms_utility.format_error_stack,
                                    dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

    RETURN vo_result;

END fn_get_trunk_u2000;

FUNCTION fn_add_trunk_u2000
(
    vi_username    VARCHAR2,
    vi_password    VARCHAR2,
    vi_ip_info     VARCHAR2,
    vi_t_username  VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER

) RETURN NUMBER IS

--INTERFACE VARIABLES
    vv_mid_id_user        NUMBER := 1;
    vv_log_message        VARCHAR2(2000);
    vv_exe_time           NUMBER := dbms_utility.get_time;
    vv_sid                NUMBER;
    vv_do_log             CHAR;
    vv_name_interface     VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface       NUMBER;
    vv_id_codsystem       NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
    get_trunk_result                NUMBER;
    get_trunk_message               VARCHAR(50);
    add_trunk_result                NUMBER;
    add_trunk_message               VARCHAR(50);
    get_max_trunk_id                NUMBER;
    ssh_message                     VARCHAR2(70);
    ssh_result                      NUMBER;
    count_pbx_table                 NUMBER;
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA

    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;

--END INTERFACE DATA


    SELECT COUNT(HOSTED.TRUNK_ID) INTO count_pbx_table FROM MIDWARE.HOSTED_PBX_U2000 HOSTED WHERE HOSTED.PHONE_NUM = vi_t_username AND HOSTED.DELETED_AT IS NULL;

    IF (count_pbx_table = 1) THEN
        vo_message := 'error: Unable to add phone number '|| vi_t_username ||' already exist in the Midware U2000 Table';
        vo_result  := -2300;
                dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        --Exectute MID Log Execution
                pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                            vv_mid_id_user,
                                            vv_exe_time);
        --END Exectute MID Log Execution  
        RETURN vo_result;
    END IF;

    SELECT MAX(HOSTED.TRUNK_ID) INTO get_max_trunk_id FROM MIDWARE.HOSTED_PBX_U2000 HOSTED;

    get_max_trunk_id := get_max_trunk_id + 1;

    INSERT INTO MIDWARE.HOSTED_PBX_U2000(TRUNK_ID, ROUTE_ID, SUB_ROUTE_ID, PHONE_NUM, CREATED_AT, UPDATED_AT, DELETED_AT)
    VALUES (get_max_trunk_id, get_max_trunk_id, get_max_trunk_id, vi_t_username, SYSDATE, NULL, NULL);
    

    get_trunk_result := pck_pbx.fn_get_trunk_u2000 (vi_username, vi_password, vi_ip_info, vi_t_username, get_trunk_message, get_trunk_result);

    IF (get_trunk_result = -2100) THEN
        ROLLBACK;
        vo_message := 'error: '|| 'No data found. Please verify if '||vi_t_username||' exist in the Midware U2000 Table';
        vo_result  := get_trunk_result;
                        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        --Exectute MID Log Execution
                pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                            vv_mid_id_user,
                                            vv_exe_time);
        --END Exectute MID Log Execution  
        RETURN vo_result;    
    ELSIF (get_trunk_result = 0) THEN
        ROLLBACK;
        vo_message := 'error: '|| 'ID exist on the U2000 Node.  Please verify ID Number '||get_max_trunk_id||' on U2000 Node or Midware U2000 Table';
        vo_result  := -2200;
                        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        --Exectute MID Log Execution
                pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                            vv_mid_id_user,
                                            vv_exe_time);
        --END Exectute MID Log Execution  
        RETURN vo_result;  
    ELSIF (get_trunk_result != 21) THEN
        ROLLBACK;
        vo_message := 'error: '|| get_trunk_message;
        vo_result  := get_trunk_result;
                        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        --Exectute MID Log Execution
                pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                            vv_mid_id_user,
                                            vv_exe_time);
        --END Exectute MID Log Execution  
        RETURN vo_result;    
    END IF;

    ssh_message := PCK_PBX.FN_SSH_CONNECT('add_telnet_1.sh '||vi_t_username||' '||get_max_trunk_id);

    ssh_result := regexp_replace(ssh_message, '[^[:digit:]]', '');

     IF (ssh_result > 0) THEN
        ROLLBACK;
        vo_message := regexp_replace(ssh_message, '[^a-z and ^A-Z]', '');
        vo_result := ssh_result;
        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);
        --Exectute MID Log Execution
                pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                            vv_mid_id_user,
                                            vv_exe_time);
        --END Exectute MID Log Execution

        RETURN vo_result;
    END IF;

    COMMIT;
    vo_message := 'success';
    vo_result := 0;
        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

--Exectute MID Log Execution
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
--END Exectute MID Log Execution    

    RETURN vo_result;

    --When any errors then it logs the error

    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            vo_result := -8000;
            vo_message := sqlerrm;
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message,
                                        vv_id_interface,
                                        vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                    dbms_utility.format_error_stack,
                                    dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

    RETURN vo_result;

END fn_add_trunk_u2000;

FUNCTION fn_reconnect_subscriber
(
    vi_username    VARCHAR2,
    vi_password    VARCHAR2,
    vi_ip_info     VARCHAR2,
    vi_t_username  VARCHAR2,
    vo_message     OUT  VARCHAR2,
    vo_result      OUT  NUMBER

) RETURN NUMBER AS

 --FUNCTION VARIABLES
    vv_http_url                  VARCHAR2(2000);
    vv_http_parameter            VARCHAR2(2000);
    vv_cnt                       NUMBER := 0;
    vv_tenants                   VARCHAR2(1000);
    vv_http_status               VARCHAR2(100);
    vv_http_response             VARCHAR2(30000);
    pbx_number                   VARCHAR2(200) := 'PBX-' || vi_t_username;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
    vv_mid_id_user               NUMBER := 1;
    vv_log_message               VARCHAR2(3000);
    vv_exe_time                  NUMBER := dbms_utility.get_time;
    vv_sid                       NUMBER;
    vv_do_log                    CHAR;
    vv_name_interface            VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
    vv_id_interface              NUMBER;
    vv_id_codsystem              NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
    http_status                  VARCHAR2(3);
    http_url                     VARCHAR(1000);
    http_parameter               VARCHAR2(1000);
    http_response                VARCHAR2(12000);
    vo_post_auth_token    VARCHAR2(1000);
    vo_post_auth_message  VARCHAR2(1000);
    vo_post_auth_result   INT;

    get_tenant_id_message        VARCHAR2(1000);
    get_tenant_id_result         NUMBER;
    get_tenant_id_tenant_id      VARCHAR2(100);
    get_tenant_id_resource_id    VARCHAR2(100);
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        to_number(substr(dbms_session.unique_session_id, 1, 4), 'XXXX')
    INTO vv_sid
    FROM
        dual;

    SELECT
        cod_system
    INTO vv_id_codsystem
    FROM
        mid_system
    WHERE
        nm_system = gv_codsystem;

    SELECT
        id_interface
    INTO vv_id_interface
    FROM
        mid_interface
    WHERE
            nm_interface = vv_name_interface
        AND cod_system = vv_id_codsystem;

    vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result);

    IF ( vv_mid_id_user < 0 ) THEN
        vv_log_message := 'USER:'
                          || vi_username
                          || '||'
                          || vi_ip_info
                          || '||'
                          || vo_message;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    1,
                                    vv_exe_time);

        RETURN vo_result;
    END IF;

    vv_log_message := vi_ip_info;
    --END INTERFACE DATA

--NUMERIC VALIDATION
    IF NOT REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$')  THEN
        VO_MESSAGE := 'Error: Trunk must be 7 digit numeric value';
        VO_RESULT := -1021;

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);
        RETURN VO_RESULT;
    END IF; 
--END NUMERIC VALIDATION

    GET_TENANT_ID_RESULT := pck_pbx.fn_get_tenant_id(VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, GET_TENANT_ID_TENANT_ID, GET_TENANT_ID_RESOURCE_ID, GET_TENANT_ID_MESSAGE, GET_TENANT_ID_RESULT);

    IF(GET_TENANT_ID_RESULT != 0) THEN
        vo_message := GET_TENANT_ID_MESSAGE;
        vo_result  :=  GET_TENANT_ID_RESULT;

        dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        return vo_result;
    END IF;

    vo_post_auth_result := pck_pbx.FN_POST_AUTHENTICATE_TENANT(vi_username, vi_password, vi_ip_info, vo_post_auth_token, vo_post_auth_message, vo_post_auth_result);

    IF ( vo_post_auth_result = 0 ) THEN
        http_parameter := '
        {
            "action":"start-tenant",
            "token":"'||vo_post_auth_token||'",
            "id":"'||get_tenant_id_tenant_id||'"         
        }';

        /*Removed as no longer necessary  "whitelist": [{"address":"172.21.56.33", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]},{"address":"172.21.56.30", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]}]*/

        MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,http_parameter, 'application/json',HTTP_STATUS,  HTTP_RESPONSE);
        IF ( instr(http_response, 'pending') >= 1 ) THEN
            vo_result := 0;
            vo_message := 'success';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        ELSIF ( instr(http_response, 'success') >= 1 ) THEN
            vo_result := -2042;
            vo_message := 'error: Tenant already active';
            dbms_output.put_line(to_char($$plsql_line)
                                 || ': '
                                 || vi_username
                                 || '|'
                                 || vi_password
                                 || '|'
                                 || vi_ip_info
                                 || '|'
                                 || vi_t_username
                                 || '|'
                                 || vo_message
                                 || '|'
                                 || vo_result);

            pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                        vv_mid_id_user,
                                        vv_exe_time);

            RETURN vo_result;
        END IF;

    END IF;

    vo_result := -2010;
    vo_message := 'Error: Tenant Authentication Unssuccessful';
    dbms_output.put_line(to_char($$plsql_line)
                         || ': '
                         || vi_username
                         || '|'
                         || vi_password
                         || '|'
                         || vi_ip_info
                         || '|'
                         || vi_t_username
                         || '|'
                         || vo_message
                         || '|'
                         || vo_result);

    pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                vv_mid_id_user,
                                vv_exe_time);

    RETURN vo_result;

--Global exception handling
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        vo_result := -8000;
        vo_message := 'ERROR:'
                          || vv_log_message
                          || '|'
                          || sqlerrm;
        pck_middle.mid_log_execution(vv_sid, sysdate, vv_log_message, vv_id_interface, vv_id_codsystem,
                                    vv_mid_id_user,
                                    vv_exe_time);

        pck_middle.mid_log_error(vv_sid, sysdate, vv_id_interface, vv_id_codsystem, sqlerrm,
                                dbms_utility.format_error_stack,
                                dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.
        RETURN vo_result;

END fn_reconnect_subscriber;

FUNCTION FN_DELETE_TRUNK_U2000 (VI_USERNAME IN VARCHAR2, VI_PASSWORD IN VARCHAR2, VI_IP_INFO IN VARCHAR2, VI_T_USERNAME IN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT INT) 
RETURN NUMBER AS

--INTERFACE VARIABLES
    VV_MID_ID_USER        NUMBER := 1;
    VV_LOG_MESSAGE        VARCHAR2(2000);
    VV_EXE_TIME           NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID                NUMBER;
    VV_DO_LOG             CHAR;
    VV_NAME_INTERFACE     VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE       NUMBER;
    VV_ID_CODSYSTEM       NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
    DLT_TRUNK_ID                NUMBER;
    PBX_CNT                     NUMBER;
    SSH_MESSAGE                 VARCHAR2(100);
    SSH_RESULT                  NUMBER;
    VO_T_USERNAME               NUMBER := VI_T_USERNAME;
    VO_U2000_MESSAGE            VARCHAR2(1000);
    VO_U2000_RESULT             INT;
--END PROGRAM VARIABLES

BEGIN

--INTERFACE DATA
    SELECT
        TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID, 1, 4), 'XXXX')
    INTO VV_SID
    FROM
        DUAL;

    SELECT
        COD_SYSTEM
    INTO VV_ID_CODSYSTEM
    FROM
        MID_SYSTEM
    WHERE
        NM_SYSTEM = GV_CODSYSTEM;

    SELECT
        ID_INTERFACE
    INTO VV_ID_INTERFACE 
    FROM
        MID_INTERFACE
    WHERE
            NM_INTERFACE = VV_NAME_INTERFACE
        AND COD_SYSTEM = VV_ID_CODSYSTEM;

    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(TRIM(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF ( VV_MID_ID_USER < 0 ) THEN
        VV_LOG_MESSAGE := 'USER:'
                          || VI_USERNAME
                          || '||'
                          || VI_IP_INFO
                          || '||'
                          || VO_MESSAGE;

        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID, SYSDATE, VV_LOG_MESSAGE, VV_ID_INTERFACE, VV_ID_CODSYSTEM,
                                    1,
                                    VV_EXE_TIME);

  RETURN VO_RESULT;
END IF;

    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA


  --FN_GET_TRUNK_U2000 Function CALL
  VO_U2000_RESULT := PCK_PBX.FN_GET_TRUNK_U2000 (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VO_T_USERNAME, VO_U2000_MESSAGE, VO_U2000_RESULT);


  SELECT TRUNK_ID INTO DLT_TRUNK_ID
  FROM MIDWARE.HOSTED_PBX_U2000 
  WHERE PHONE_NUM = VO_T_USERNAME AND DELETED_AT IS NULL;


    --ERROR Handling for FN_GET_TRUNK_U2000
    IF (VO_U2000_RESULT > 0) THEN
      VO_MESSAGE := 'ERROR: Verify U2000 error code '||VO_U2000_RESULT||' for Trunk ID: '|| DLT_TRUNK_ID;
      VO_RESULT := VO_U2000_RESULT;
    RETURN VO_RESULT;
    ELSIF (VO_U2000_RESULT < 0 ) THEN
      VO_MESSAGE := 'ERROR: '|| 'Trunk not found. Please verify if '||VO_T_USERNAME||' exists in the Midware U2000 Table';
      VO_RESULT := VO_U2000_RESULT;
    RETURN VO_RESULT;
  END IF;


  --Execute Delete on U2000
  SSH_MESSAGE := PCK_PBX.FN_SSH_CONNECT(GV_DELETE_U2000 ||' '||DLT_TRUNK_ID);
  SSH_RESULT := regexp_replace(SSH_MESSAGE, '[^[:digit:]]', '');


    --ERROR Handling for U2000
    IF (SSH_RESULT > 0) THEN
      VO_MESSAGE := regexp_replace(SSH_MESSAGE, '[^a-z and ^A-Z]', '');
      VO_RESULT := SSH_RESULT;
    RETURN VO_RESULT;
  END IF;


  UPDATE MIDWARE.HOSTED_PBX_U2000 
  SET DELETED_AT = SYSDATE 
  WHERE TRUNK_ID = DLT_TRUNK_ID AND DELETED_AT IS NULL;
  commit;

  VO_MESSAGE := 'SUCCESS';
  VO_RESULT := 0;
RETURN VO_RESULT;


--GLOBAL EXCEPTION HANDLING
  EXCEPTION WHEN OTHERS THEN
  ROLLBACK;
        VO_RESULT := -8000;
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
RETURN VO_RESULT; 

END FN_DELETE_TRUNK_U2000;

FUNCTION FN_SUSPEND_SUBSCRIBER (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER AS

    --INTERFACE VARIABLES
    VV_MID_ID_USER NUMBER := 1; 
    VV_LOG_MESSAGE VARCHAR2(2000);
    VV_EXE_TIME NUMBER := DBMS_UTILITY.GET_TIME;
    VV_SID NUMBER;
    VV_DO_LOG CHAR; 
    VV_NAME_INTERFACE VARCHAR2(50) := UTL_CALL_STACK.SUBPROGRAM(1)(2);
    VV_ID_INTERFACE NUMBER;
    VV_ID_CODSYSTEM NUMBER;
    --END INTERFACE VARIABLES
    --FUNCTION VARIABLES
        VV_NUM NUMBER := 1;
        VV_SEARCH_TXT varchar2(100);
        VO_TENANTS        VARCHAR2(2000);
        --AUTHENTICATION VARIABLES
        AUTH_TOKEN              VARCHAR2(1000);
        AUTH_RESULT             NUMBER;
        --END AUTHENTICATION VARIABLES        
        --FIND VARIABLES
        FIND_TENANT_ID          VARCHAR2(1000);
        FIND_RESULT             NUMBER;
        FIND_HTTP_STATUS        VARCHAR2(100);
        --END FIND VARIABLES
        --SUS VARIALBLES
        SUS_HTTP_RESPONSE       VARCHAR2(10000);
        SUS_HTTP_PARAMETER      VARCHAR2(1000);
        SUS_HTTP_STATUS         VARCHAR2(100);
        --END SUS VARIALBLES
    --END FUNCTION VARIABLES
BEGIN
    --INTERFACE DATA
    SELECT TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') INTO VV_SID FROM DUAL; 
    SELECT COD_SYSTEM INTO VV_ID_CODSYSTEM FROM MID_SYSTEM WHERE NM_SYSTEM = GV_CODSYSTEM;
    SELECT ID_INTERFACE INTO VV_ID_INTERFACE FROM MID_INTERFACE WHERE NM_INTERFACE = VV_NAME_INTERFACE AND COD_SYSTEM = VV_ID_CODSYSTEM;
    VV_MID_ID_USER := PCK_MIDDLE.MID_INTERFACE_LOGIN(trim(VI_USERNAME), VI_PASSWORD, VV_ID_INTERFACE, VO_MESSAGE, VO_RESULT);

    IF (VV_MID_ID_USER < 0) THEN
      VV_LOG_MESSAGE := 'USER:'||VI_USERNAME||'||'||VI_IP_INFO||'||'||VO_MESSAGE; 
      PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, 1,VV_EXE_TIME);
      RETURN VO_RESULT;
    END IF;
    VV_LOG_MESSAGE := VI_IP_INFO;
    --END INTERFACE DATA

    IF REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$') THEN

        AUTH_RESULT:= FN_POST_AUTHENTICATE_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, AUTH_TOKEN, VO_MESSAGE, VO_RESULT);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||AUTH_RESULT||'|'||AUTH_TOKEN||'|'||AUTH_MESSAGE);

        FIND_RESULT:= FN_GET_TENANT (VI_USERNAME, VI_PASSWORD, VI_IP_INFO, VI_T_USERNAME, VO_TENANTS, VO_MESSAGE, VO_RESULT);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_TENANTS);

        IF VO_RESULT = 0 THEN

            VV_SEARCH_TXT := '<ID>';
            VV_NUM := INSTR(VO_TENANTS,VV_SEARCH_TXT,VV_NUM);
            FIND_TENANT_ID := TO_CHAR(SUBSTR(VO_TENANTS, VV_NUM + LENGTH(VV_SEARCH_TXT),INSTR(VO_TENANTS, '</ID>',VV_NUM + LENGTH(VV_SEARCH_TXT))-(VV_NUM + LENGTH(VV_SEARCH_TXT))));
            --DBMS_OUTPUT.PUT_LINE(to_char($$PLSQL_LINE)||':'||FIND_TENANT_ID);

            VV_SEARCH_TXT := '<STATUS>';
            VV_NUM := INSTR(VO_TENANTS,VV_SEARCH_TXT,VV_NUM);
            FIND_HTTP_STATUS := TO_CHAR(SUBSTR(VO_TENANTS, VV_NUM + LENGTH(VV_SEARCH_TXT),INSTR(VO_TENANTS, '</STATUS>',VV_NUM + LENGTH(VV_SEARCH_TXT))-(VV_NUM + LENGTH(VV_SEARCH_TXT))));
            --DBMS_OUTPUT.PUT_LINE(to_char($$PLSQL_LINE)||':'||FIND_HTTP_STATUS);

            IF FIND_HTTP_STATUS != 'running' THEN
                VO_RESULT:= -4020;
                VO_MESSAGE:= 'Tenant already stopped';
            ELSE
                SUS_HTTP_PARAMETER:='{"action":"stop-tenant", "id":"'||FIND_TENANT_ID||'",'||'"token":"'||AUTH_TOKEN||'"}';
                MIDWARE.MID_HTTP_POST(GV_HTTP_TENANT_URL ,SUS_HTTP_PARAMETER, 'application/json', SUS_HTTP_STATUS, SUS_HTTP_RESPONSE);
                --dbms_output.put_line(to_char($$plsql_line)||'|'||SUS_HTTP_STATUS||'|'||SUS_HTTP_RESPONSE);

                IF SUS_HTTP_STATUS != 200 THEN
                    VO_RESULT:= -4021;
                    VO_MESSAGE:= SUS_HTTP_RESPONSE;
                ELSE
                    VO_RESULT:= 0;
                    VO_MESSAGE:= 'Stopping Tenant';
                END IF;
            END IF;
        END IF;
    ELSE
        SELECT 'Error: Username must be 7 digit numeric value' into VO_MESSAGE FROM dual;
        VO_RESULT := -2001;
    END IF;
    PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
    RETURN VO_RESULT;
    EXCEPTION
    WHEN OTHERS
    THEN
        VO_RESULT := -8000;
        VO_MESSAGE := 'Contact BTL MIDWARE ADMIN';
        VV_LOG_MESSAGE := 'ERROR:'||VV_LOG_MESSAGE||'|'||SQLERRM;
        PCK_MIDDLE.MID_LOG_EXECUTION(VV_SID ,SYSDATE,VV_LOG_MESSAGE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, VV_MID_ID_USER,VV_EXE_TIME);
        PCK_MIDDLE.MID_LOG_ERROR(VV_SID,SYSDATE,VV_ID_INTERFACE,VV_ID_CODSYSTEM, SQLERRM, DBMS_UTILITY.FORMAT_ERROR_STACK,DBMS_UTILITY.FORMAT_CALL_STACK||DBMS_UTILITY.FORMAT_ERROR_BACKTRACE);--store the errors or present all errors found.
   RETURN VO_RESULT;
END FN_SUSPEND_SUBSCRIBER;

FUNCTION fn_ssh_connect 
(
    inputs IN VARCHAR2
) RETURN VARCHAR2 AS

    LANGUAGE JAVA
    NAME 'SshConnection.SshConnect (java.lang.String) return java.lang.String';

END PCK_PBX;