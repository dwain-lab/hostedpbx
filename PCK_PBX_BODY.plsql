CREATE OR REPLACE PACKAGE BODY pck_pbx AS

    FUNCTION fn_post_authenticate (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_token        OUT             VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

        vv_http_url         VARCHAR2(2000);
        vv_http_parameter   VARCHAR2(2000);
        vv_status           VARCHAR2(1000) := NULL;
        vv_token            VARCHAR2(2000) := NULL;
        vv_message          VARCHAR2(2000) := NULL;
        vv_http_status      VARCHAR2(100);
        vv_http_response    VARCHAR2(20000);

    --INTERFACE VARIABLES
        vv_mid_id_user      NUMBER := 1;
        vv_log_message      VARCHAR2(2000);
        vv_exe_time         NUMBER := dbms_utility.get_time;
        vv_sid              NUMBER;
        vv_do_log           CHAR;
        vv_name_interface   VARCHAR2(24) := utl_call_stack.subprogram(1)(2);
        vv_id_interface     NUMBER;
        vv_id_codsystem     NUMBER;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA

    --VV_HTTP_URL      :=GV_HTTP_URL;
        vv_http_url := 'https://'
                       || 'PBX-'
                       || vi_t_username
                       || '.'
                       || gv_http_url
                       || '/authenticate';
    --dbms_output.put_line(VV_HTTP_URL);
    --VV_HTTP_PARAMETER:=GV_HTTP_PARAMETER;

        vv_http_parameter := 'key=' || gv_key;
    --dbms_output.put_line(VV_HTTP_PARAMETER);
        midware.test_http_post(vv_http_url, vv_http_parameter, vv_http_status, vv_http_response);
    --dbms_output.put_line(HTTP_RESPONSE);

    --SELECT json_value(HTTP_RESPONSE, '$.status'), json_value(HTTP_RESPONSE, '$.data.token') into VV_STATUS, VV_Token FROM dual;
        SELECT
            JSON_VALUE(vv_http_response, '$.status')
        INTO vv_status
        FROM
            dual;
   --VO_STATUS:=VV_STATUS;

        IF vv_status = 'success' THEN
            SELECT
                JSON_VALUE(vv_http_response, '$.data.token')
            INTO vv_token
            FROM
                dual;

            vo_token := vv_token;
        ELSE
            SELECT
                JSON_VALUE(vv_http_response, '$.message')
            INTO vv_message
            FROM
                dual;

            vo_result := -5000;
            vo_message := 'Error: Tenant Authentication Unsuccessful';
            RETURN vo_result;
        END IF;

        vo_result := 0;
        vo_message := 'SUCCESS';    
    --DBMS_OUTPUT.PUT_LINE ('Status :'||VV_STATUS||' Message :'||VV_Message||' Token :'||VV_Token);   
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_post_authenticate;

    FUNCTION fn_add_trunk_cpbx (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_t_password   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user                  NUMBER := 1;
        vv_log_message                  VARCHAR2(2000);
        vv_exe_time                     NUMBER := dbms_utility.get_time;
        vv_sid                          NUMBER;
        vv_do_log                       CHAR;
        vv_name_interface               VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                 NUMBER;
        vv_id_codsystem                 NUMBER;
--END INTERFACE VARIABLES   

--PROGRAM VARIABLES
        vv_description                  VARCHAR(20) := '%2B501' || vi_t_username;
        vv_outgoing_username            VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_username
        vv_outgoing_defaultuser         VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_defaultuser
        vv_outgoing_remotesecret        VARCHAR(50) := vi_t_password; --outgoing_remotesecret
        vv_outgoing_fromuser            VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_fromuser
        vv_trunk_cid                    VARCHAR(50) := '%2B501' || vi_t_username; --trunk_cid
        http_status                     VARCHAR2(3);
        http_url                        VARCHAR(1000);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
        http_url_authenticate           VARCHAR2(100) := 'https://PBX-'
                                               || vi_t_username
                                               || '.'
                                               || gv_http_url
                                               || '/authenticate';
--    http_url_authenticate    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --http_url_create_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/create_trunk';
        http_url_create_trunk           VARCHAR(100) := 'https://PBX-'
                                              || vi_t_username
                                              || '.'
                                              || gv_http_url
                                              || '/create_trunk';
--    http_url_create_trunk    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
        http_parameter                  VARCHAR2(1000);
        http_response                   VARCHAR2(12000);
        vo_post_auth_result             NUMBER;
        vo_post_auth_message            VARCHAR2(1000);
        vo_post_auth_token              VARCHAR2(1000);
        add_trunk_u2000_result          NUMBER;
        add_trunk_u2000_message         VARCHAR(500);
        add_trunk_helper_cpbx_result    NUMBER;
        add_trunk_helper_cpbx_message   VARCHAR(500);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
--END INTERFACE DATA

--NUMERIC VALIDATION
        IF NOT regexp_like(vi_t_username, '^[0-9]{7}$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -1021;
            RETURN vo_result;
        END IF;

        add_trunk_helper_cpbx_result := pck_pbx.fn_add_trunk_helper_cpbx(vi_username, vi_password, vi_ip_info, vi_t_username, vi_t_password

        , vi_product, add_trunk_helper_cpbx_message, add_trunk_helper_cpbx_result);

        IF ( add_trunk_helper_cpbx_result = -2001 ) THEN
            vo_message := 'error: Unable to proccess request due to pbx not created';
            vo_result := -2041;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        END IF;

        add_trunk_u2000_result := pck_pbx.fn_add_trunk_u2000(vi_username, vi_password, vi_ip_info, vi_t_username, add_trunk_u2000_message

        , add_trunk_u2000_result);

        IF ( add_trunk_u2000_result = 0 AND add_trunk_helper_cpbx_result = 0 ) THEN
            vo_message := 'Success';
            vo_result := 0;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        ELSIF ( add_trunk_u2000_result != 0 AND add_trunk_helper_cpbx_result = 0 ) THEN
            vo_message := 'partial success: success: cpbx | '
                          || 'error: U2000 code:'
                          || add_trunk_u2000_result
                          || 'cpbx message:'
                          || add_trunk_u2000_message;
            vo_result := -6000;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        ELSIF ( add_trunk_helper_cpbx_result != 0 AND add_trunk_u2000_result = 0 ) THEN
            vo_message := 'partial success: success: U2000 | '
                          || 'error: cpbx code:'
                          || add_trunk_helper_cpbx_result
                          || 'cpbx message:'
                          || add_trunk_helper_cpbx_message;
            vo_result := -6000;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        ELSE
            vo_message := 'CPBX Error Code: '
                          || add_trunk_helper_cpbx_result
                          || 'CPBX Error Message: '
                          || add_trunk_helper_cpbx_message
                          || ' U2000 Error Code: '
                          || add_trunk_u2000_result
                          || ' U2000 Error Message: '
                          || add_trunk_u2000_message;

            vo_result := -2041;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        END IF;

--When any errors then it logs the error

    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_add_trunk_cpbx;

    FUNCTION fn_add_trunk_helper_cpbx (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_t_password   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user             NUMBER := 1;
        vv_log_message             VARCHAR2(2000);
        vv_exe_time                NUMBER := dbms_utility.get_time;
        vv_sid                     NUMBER;
        vv_do_log                  CHAR;
        vv_name_interface          VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface            NUMBER;
        vv_id_codsystem            NUMBER;
--END INTERFACE VARIABLES   

--PROGRAM VARIABLES
        vv_description             VARCHAR(20) := '%2B501' || vi_t_username;
        vv_outgoing_username       VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_username
        vv_outgoing_defaultuser    VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_defaultuser
        vv_outgoing_remotesecret   VARCHAR(50) := vi_t_password; --outgoing_remotesecret
        vv_outgoing_fromuser       VARCHAR(50) := '%2B501' || vi_t_username; --outgoing_fromuser
        vv_trunk_cid               VARCHAR(50) := '%2B501' || vi_t_username; --trunk_cid
        vv_register                VARCHAR(400) := '%2B501'
                                    || vi_t_username
                                    || '%40'
                                    || gv_outgoing_host
                                    || '---mtob-'
                                    || gv_outbound_proxy
                                    || '%3A'
                                    || vi_t_password
                                    || '%3A%2B501'
                                    || vi_t_username
                                    || '%40'
                                    || gv_outgoing_host
                                    || '%40'
                                    || gv_outbound_proxy
                                    || '%3A'
                                    || gv_outgoing_port
                                    || '%2F%2B501'
                                    || vi_t_username; --register
        http_status                VARCHAR2(3);
        http_url                   VARCHAR(1000);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
        http_url_authenticate      VARCHAR2(100) := 'https://PBX-'
                                               || vi_t_username
                                               || '.'
                                               || gv_http_url
                                               || '/authenticate';
--    http_url_authenticate    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/authenticate';
    --http_url_create_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/create_trunk';
        http_url_create_trunk      VARCHAR(100) := 'https://PBX-'
                                              || vi_t_username
                                              || '.'
                                              || gv_http_url
                                              || '/create_trunk';
--    http_url_create_trunk    VARCHAR(100) := 'https://'||'PBX-'||vi_t_username||'.'||gv_http_url||'/create_trunk';
        http_parameter             VARCHAR2(1000);
        http_response              VARCHAR2(12000);
        vo_post_auth_result        NUMBER;
        vo_post_auth_message       VARCHAR2(1000);
        vo_post_auth_token         VARCHAR2(1000);
        add_trunk_u2000_result     NUMBER;
        add_trunk_u2000_message    VARCHAR(100);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
--END INTERFACE DATA
        vo_post_auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username, vo_post_auth_message
        , vo_post_auth_token, vo_post_auth_result);

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
                              || gv_outgoing_insecure
                              || '&trunk_cid=%22%22%20%3C%2B501'
                              || vi_t_username
                              || '%3E'
                              || '&register='
                              || vv_register
                              || '&register_flag=0';

            midware.test_http_post(http_url_create_trunk, http_parameter, http_status, http_response);
            IF ( instr(http_response, 'success') >= 1 ) THEN
                vo_result := 0;
                vo_message := 'success';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            ELSE
                vo_result := -2002;
                vo_message := http_response;
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            END IF;

        END IF;

        vo_result := -2001;
        vo_message := 'status:error, Unable to authenticate request.';
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;

--When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_add_trunk_helper_cpbx;

    FUNCTION fn_add_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_plan         VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user         NUMBER := 1;
        vv_log_message         VARCHAR2(2000);
        vv_exe_time            NUMBER := dbms_utility.get_time;
        vv_sid                 NUMBER;
        vv_do_log              CHAR;
        vv_name_interface      VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface        NUMBER;
        vv_id_codsystem        NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        vv_hostname            VARCHAR2(25) := 'PBX-' || vi_t_username;
        vv_plan                VARCHAR2(50);
        http_status            VARCHAR2(3);
        http_url               VARCHAR(1000);
        http_parameter         VARCHAR2(1000);
        http_response          VARCHAR2(12000);
        vo_post_auth_result    INT;
        vo_post_auth_message   VARCHAR2(1000);
        vo_post_auth_token     VARCHAR2(1000);
        vv_plan2               VARCHAR2(100);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

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
        vv_plan2 := upper(vi_plan);

--NUMERIC VALIDATION
        IF NOT regexp_like(vi_t_username, '^[0-9]{7}$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -2001;
            RETURN vo_result;
        END IF;

        IF ( vv_plan2 = 'S' ) THEN
            vv_plan := gv_plan_s;
        ELSIF ( vv_plan2 = 'M' ) THEN
            vv_plan := gv_plan_m;
        ELSIF ( vv_plan2 = 'L' ) THEN
            vv_plan := gv_plan_l;
        ELSE
            vo_result := -2002;
            vo_message := 'Error: Invalid plan';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        vo_post_auth_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vo_post_auth_token, vo_post_auth_message

        , vo_post_auth_result);

        IF ( vo_post_auth_result = 0 ) THEN
            http_parameter := '
        {
            "action":"create-tenant",
            "token":"'
                              || vo_post_auth_token
                              || '",
            "name":"'
                              || vv_hostname
                              || '",
            "image":"btl-cpbx-5.1.22.1",
            "resource_plan": "'
                              || vv_plan
                              || '",
            "system_name": "'
                              || vv_hostname
                              || '"            
        }';

        /*Removed as no longer necessary  "whitelist": [{"address":"172.21.56.33", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]},{"address":"172.21.56.30", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]}]*/

            midware.mid_http_post(gv_http_tenant_url, http_parameter, 'application/json', http_status, http_response);
            IF ( instr(http_response, 'pending') >= 1 ) THEN
                vo_result := 0;
                vo_message := 'success';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            ELSE
                vo_result := -4010;
                vo_message := 'Error: Tenant already exists';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            END IF;

        END IF;

        vo_result := -4000;
        vo_message := 'Error: MT Manger Authentication Unssuccessful';
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;

--When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_add_subscriber;

    FUNCTION fn_post_authenticate_tenant (
        vi_username   VARCHAR2,
        vi_password   VARCHAR2,
        vi_ip_info    VARCHAR2,
        vo_t_token    OUT           VARCHAR2,
        vo_message    OUT           VARCHAR2,
        vo_result     OUT           NUMBER
    ) RETURN NUMBER AS


    --FUNCTION VARIABLES

        vv_http_url         VARCHAR2(2000);
        vv_http_parameter   VARCHAR2(2000);
        vv_status           VARCHAR2(1000);
        vv_token            VARCHAR2(2000);
        vv_message          VARCHAR2(2000);
        vv_http_status      VARCHAR2(100);
        vv_http_response    VARCHAR2(20000);
    --END FUNCTION VARIABLES
    BEGIN
        vv_http_url := pck_pbx.gv_http_tenant_url;
        vv_http_parameter := '{"action":"authenticate","username":"admin","password":"fWaBeeZYXmeKOZ"}';
        midware.test_http_post(vv_http_url, vv_http_parameter, vv_http_status, vv_http_response);
    --dbms_output.put_line(HTTP_RESPONSE);
        SELECT
            JSON_VALUE(vv_http_response, '$.status')
        INTO vv_status
        FROM
            dual;

        IF vv_status = 'success' THEN
            SELECT
                JSON_VALUE(vv_http_response, '$.token')
            INTO /*VV_STATUS,*/ vv_token
            FROM
                dual;

            vo_t_token := vv_token;
        ELSE
            SELECT
                JSON_VALUE(vv_http_response, '$.error')
            INTO /*VV_STATUS,*/ vv_message
            FROM
                dual;

            vo_result := -4000;
            vo_message := 'Error: MT Manger Authentication Unssuccessful';
            RETURN vo_result;
        END IF;

        vo_result := 0;
        RETURN vo_result;
    END fn_post_authenticate_tenant;

    FUNCTION fn_delete_subscriber (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             INT
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user             NUMBER := 1;
        vv_log_message             VARCHAR2(2000);
        vv_exe_time                NUMBER := dbms_utility.get_time;
        vv_sid                     NUMBER;
        vv_do_log                  CHAR;
        vv_name_interface          VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface            NUMBER;
        vv_id_codsystem            NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        vo_t_username              VARCHAR(50);
        vo_trunk_id                NUMBER;
        vo_find_result             NUMBER;
        vo_find_message            VARCHAR(100);
        http_status                VARCHAR2(3);
        http_url                   VARCHAR(1000);
        http_parameter             VARCHAR2(1000);
        http_response              VARCHAR2(12000);
        vo_http_response_result    INT;
        vo_http_response_message   VARCHAR2(1000);
        vo_post_auth_result        INT;
        vo_post_auth_message       VARCHAR2(1000);
        vo_post_auth_token         VARCHAR2(1000);
        vo_u2000_delete_result     INT;
        vo_u2000_delete_message    VARCHAR2(1000);
        http_url_authenticate      VARCHAR2(100) := 'https://PBX-'
                                               || vi_t_username
                                               || '.'
                                               || gv_http_url
                                               || '/authenticate';
        http_url_delete_trunk      VARCHAR2(100) := 'https://PBX-'
                                               || vi_t_username
                                               || '.'
                                               || gv_http_url
                                               || '/destroy_trunk/';
        vo_t_password              VARCHAR2(100);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA


    --NULL VALIDATION
        IF vi_t_username IS NULL OR length(trim(vi_t_username)) = 0 THEN
            vo_message := 'Error: Trunk is missing';
            vo_result := -2000;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

    --NUMERIC VALIDATION

        IF NOT regexp_like(vi_t_username, '^[0-9]+$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -2001;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

    --AUTHENTICATION Call

        vo_post_auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username, vo_post_auth_token

        , vo_post_auth_message, vo_post_auth_result);

        vo_find_result := pck_pbx.fn_find_trunk(vi_username, vi_password, vi_ip_info, vi_t_username, vi_product, vo_trunk_id, vo_t_username

        , vo_t_password, vo_find_result, vo_find_message);



    --Error result for FN_POST_AUTHENTICATE

        IF ( vo_post_auth_result != 0 ) THEN
            vo_result := -5000;
            vo_message := 'Error: Tenant Authentication Unsuccessful';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

    --Error result for FN_FIND_TRUNK

        IF ( vo_trunk_id < 1 OR vo_trunk_id IS NULL ) THEN
            vo_result := -2050;
            vo_message := 'Error: Trunk does not exist';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        http_url := http_url_delete_trunk || vo_trunk_id;
        http_parameter := 'token=' || vo_post_auth_token;
        midware.test_http_post(http_url, http_parameter, http_status, http_response);
        vo_u2000_delete_result := pck_pbx.fn_delete_trunk_u2000(vi_username, vi_password, vi_ip_info, vi_t_username, vo_u2000_delete_message
        , vo_u2000_delete_result);

        IF ( instr(http_response, 'success') >= 1 ) THEN
            vo_http_response_message := 'SUCCESS';
            vo_http_response_result := 0;
        ELSE
            vo_http_response_result := -5013;
            vo_http_response_message := 'Error: Unable to delete trunk';
        END IF;

        --Error result for CPBX & U2000

        IF ( vo_http_response_result != vo_u2000_delete_result ) THEN
            vo_message := 'CPBX: '
                          || vo_http_response_message
                          || ' CODE: '
                          || vo_http_response_result
                          || '. U2000: '
                          || vo_u2000_delete_message
                          || ' CODE: '
                          || vo_u2000_delete_result;

            vo_result := -6000;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        vo_message := 'SUCCESS';
        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;


--WHEN ANY ERRORS THEN IT LOGS THE ERROR
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--STORE THE ERRORS OR PRESENT ALL ERRORS FOUND.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: LOG ERROR WITH SESSION CALL

            RETURN vo_result;
    END fn_delete_subscriber;

    FUNCTION fn_get_tenant (
        vi_username   VARCHAR2,
        vi_password   VARCHAR2,
        vi_ip_info    VARCHAR2,
        vi_t_number   VARCHAR2,
        vo_tenants    OUT           VARCHAR2,
        vo_message    OUT           VARCHAR2,
        vo_result     OUT           NUMBER
    ) RETURN NUMBER AS

 --FUNCTION VARIABLES

        vv_http_url                    VARCHAR2(2000);
        vv_http_parameter              VARCHAR2(2000);
        vv_cnt                         NUMBER(5, 0) := 0;
        vv_tenants                     VARCHAR2(2000);
        vv_did                         VARCHAR(2000);
        vv_http_status                 VARCHAR2(100);
        vv_http_response               VARCHAR2(30000);
        pbx_number                     VARCHAR2(200) := 'PBX-' || vi_t_number;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
        vv_mid_id_user                 NUMBER := 1;
        vv_log_message                 VARCHAR2(2000);
        vv_exe_time                    NUMBER := dbms_utility.get_time;
        vv_sid                         NUMBER;
        vv_do_log                      CHAR;
        vv_name_interface              VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                NUMBER;
        vv_id_codsystem                NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                    VARCHAR2(3);
        http_url                       VARCHAR(1000);
        http_parameter                 VARCHAR2(1000);
        http_response                  VARCHAR2(12000);
        vo_post_auth_tenant_token      VARCHAR2(1000);
        vo_post_auth_tenant_message    VARCHAR2(1000);
        vo_post_auth_tenant_result     INT;
        vo_get_resource_plan_nm        INT;
        vo_get_plan_nm                 VARCHAR2(1000);
        vo_get_resource_plan_message   VARCHAR2(1000);
        vo_get_resource_plan_result    VARCHAR2(1000);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA


--NULL VALIDATION
        IF vi_t_number IS NULL OR length(trim(vi_t_number)) = 0 THEN
            vo_message := 'Error: Trunk is missing';
            vo_result := -2000;
            RETURN vo_result;
        END IF;

--NUMERIC VALIDATION

        IF NOT regexp_like(vi_t_number, '^[0-9]{7}$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -2001;
            RETURN vo_result;
        END IF;

  --AUTHENTICATION Call

        vo_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vo_post_auth_tenant_token

        , vo_post_auth_tenant_message, vo_post_auth_tenant_result);

        dbms_output.put_line(vo_post_auth_tenant_message);
        IF ( vo_post_auth_tenant_result = 0 ) THEN
            http_url := pck_pbx.gv_http_tenant_url;
            http_parameter := '{"action":"tenants",'
                              || '"token":"'
                              || vo_post_auth_tenant_token
                              || '"}';
            midware.mid_http_post(http_url, http_parameter, 'application/json', vv_http_status, vv_http_response);
        END IF;

        FOR rec IN (
            SELECT
                x.did_pattern,
                x.status,
                x.error,
                x.systemname
            FROM
                    JSON_TABLE ( vv_http_response, '$'
                        COLUMNS (
                            status VARCHAR ( 50 ) PATH '$.status',
                            error VARCHAR ( 50 ) PATH '$.error',
                            NESTED PATH '$.tenants[*]'
                                COLUMNS (
                                    systemname VARCHAR2 ( 100 ) PATH '$.system_name',
                                    NESTED PATH '$.did_patterns[*]'
                                        COLUMNS (
                                            did_pattern VARCHAR2 ( 200 ) PATH '$'
                                        )
                                )
                        )
                    )
                AS x
        ) LOOP IF ( rec.status = 'success' ) THEN
            IF ( rec.systemname = pbx_number ) THEN
                vv_cnt := vv_cnt + 1;
                vo_message := rec.status;
                vv_did := vv_did
                          || '<DID>'
                          || regexp_replace(rec.did_pattern, '(.{4})(.*)', '\2')
                          || '</DID>';

            END IF;

        ELSE
            vo_message := 'Error: Unable to query tenant';
            vo_result := -4012;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;
        END LOOP;

        FOR rec IN (
            SELECT
                x.status,
                x.error,
                x.id,
                x.name,
                x.systemname,
                x.mtstatus,
                x.plan
            FROM
                    JSON_TABLE ( vv_http_response, '$'
                        COLUMNS (
                            status VARCHAR ( 50 ) PATH '$.status',
                            error VARCHAR ( 50 ) PATH '$.error',
                            NESTED PATH '$.tenants[*]'
                                COLUMNS (
                                    id VARCHAR2 ( 200 ) PATH '$.id',
                                    name VARCHAR2 ( 100 ) PATH '$.name',
                                    systemname VARCHAR2 ( 100 ) PATH '$.system_name',
                                    mtstatus VARCHAR2 ( 100 ) PATH '$.status',
                                    plan VARCHAR2 ( 100 ) PATH '$.resource_plan'
                                )
                        )
                    )
                AS x
        ) LOOP IF ( rec.status = 'success' ) THEN
            IF ( rec.name = pbx_number ) THEN
                vv_cnt := vv_cnt + 1;
                vo_message := rec.status;

        --PLANNAME Call
                vo_get_resource_plan_result := pck_pbx.fn_get_resource_plan_nm(vi_username, vi_password, vi_ip_info, rec.plan, vo_get_plan_nm
                , vo_get_resource_plan_message, vo_get_resource_plan_result);

                vv_tenants := vv_tenants
                              || '<ID>'
                              || rec.id
                              || '</ID>'
                              || '<NAME>'
                              || rec.name
                              || '</NAME>'
                              || '<STATUS>'
                              || rec.mtstatus
                              || '</STATUS>'
                              || '<PLAN>'
                              || vo_get_plan_nm
                              || '</PLAN>'
                              || '<DIDS>'
                              || vv_did
                              || '</DIDS>';

            END IF;

        ELSE
            vo_message := 'Error: Unable to query tenant';
            vo_result := -4012;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;
        END LOOP;

        IF vv_cnt > 0 THEN
            vo_tenants := '<TENANT>'
                          || vv_tenants
                          || '</TENANT>';
        ELSE
            vo_message := 'Error: Tenant not found';
            vo_result := -2050;
            RETURN vo_result;
        END IF;

        vo_message := 'SUCCESS';
        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, 'USER:'
                                                      || vi_username
                                                      || '|'
                                                      || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                      );

        RETURN vo_result;

--GLOBAL EXCEPTION HANDLING
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            vo_result := -8000;
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_get_tenant;

    FUNCTION fn_get_tenant_id (
        vi_username             VARCHAR2,
        vi_password             VARCHAR2,
        vi_ip_info              VARCHAR2,
        vi_t_number             VARCHAR2,
        vo_tenants_id           OUT                     VARCHAR2,
        vo_tenant_resource_id   OUT                     VARCHAR2,
        vo_message              OUT                     VARCHAR2,
        vo_result               OUT                     NUMBER
    ) RETURN NUMBER AS

 --FUNCTION VARIABLES

        vv_http_url                   VARCHAR2(2000);
        vv_http_parameter             VARCHAR2(2000);
        vv_cnt                        NUMBER := 0;
        vv_tenants                    VARCHAR2(1000);
        vv_http_status                VARCHAR2(100);
        vv_http_response              VARCHAR2(30000);
        pbx_number                    VARCHAR2(200) := 'PBX-' || vi_t_number;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
        vv_mid_id_user                NUMBER := 1;
        vv_log_message                VARCHAR2(3000);
        vv_exe_time                   NUMBER := dbms_utility.get_time;
        vv_sid                        NUMBER;
        vv_do_log                     CHAR;
        vv_name_interface             VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface               NUMBER;
        vv_id_codsystem               NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                   VARCHAR2(3);
        http_url                      VARCHAR(1000);
        http_parameter                VARCHAR2(1000);
        http_response                 VARCHAR2(12000);
        vo_post_auth_tenant_token     VARCHAR2(1000);
        vo_post_auth_tenant_message   VARCHAR2(1000);
        vo_post_auth_tenant_result    INT;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        IF vi_t_number IS NULL OR length(trim(vi_t_number)) = 0 THEN
            vo_message := 'Error: Trunk is missing';
            vo_result := -2000;
            RETURN vo_result;
        END IF;

        vo_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vo_post_auth_tenant_token

        , vo_post_auth_tenant_message, vo_post_auth_tenant_result);

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
                pck_middle.mid_log_execution(vv_sid, SYSDATE, vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                );

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
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        vo_message := 'SUCCESS';
        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, 'USER:'
                                                      || vi_username
                                                      || '|'
                                                      || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                      );

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
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_get_tenant_id;

    FUNCTION fn_add_did (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_did_number   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER IS

--INTERFACE VARIABLES

        vv_mid_id_user                    NUMBER := 1;
        vv_log_message                    VARCHAR2(2000);
        vv_exe_time                       NUMBER := dbms_utility.get_time;
        vv_sid                            NUMBER;
        vv_do_log                         CHAR;
        vv_name_interface                 VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                   NUMBER;
        vv_id_codsystem                   NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                       VARCHAR2(3);
        http_url                          VARCHAR(1000);
        http_parameter                    VARCHAR2(1000);
        http_response                     VARCHAR2(12000);
        json_get_did_routes               VARCHAR2(1000);
        json_parameter_update_did_route   VARCHAR2(1000);
        vv_post_auth_tenant_token         VARCHAR2(1000);
        vv_post_auth_tenant_message       VARCHAR2(1000);
        vv_post_auth_tenant_result        INT;
        vv_tenant_id_result               NUMBER;
        vv_tenant_id_message              VARCHAR2(100);
        vv_tenant_id                      VARCHAR2(100);
        vv_d_username                     VARCHAR2(100) := '+501' || vi_did_number;
        vv_tenant_resource_id             VARCHAR2(100);

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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;

--END INTERFACE DATA
        vv_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vv_post_auth_tenant_token
        , vv_post_auth_tenant_message, vv_post_auth_tenant_result);

        IF ( vv_post_auth_tenant_result < 0 ) THEN
            vo_result := vv_post_auth_tenant_result;
            vo_message := vv_post_auth_tenant_message;
            RETURN vo_result;
        END IF;

        vv_tenant_id_result := pck_pbx.fn_get_tenant_id(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id

        , vv_tenant_id_message, vv_tenant_id_result);

        IF ( vv_tenant_id_result < 0 ) THEN
            vo_result := vv_tenant_id_result;
            vo_message := vv_tenant_id_message;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
            "token":"'
                               || vv_post_auth_tenant_token
                               || '"
        }
    ';
        midware.mid_http_post(gv_http_tenant_url, json_get_did_routes, 'application/json', http_status, http_response);
        IF ( instr(http_response, 'success') < 1 ) THEN
            vo_result := -4012;
            vo_message := 'Error: Unable to query tenant';
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );

            RETURN vo_result;
        END IF;

        json_parameter_update_did_route := '
    {
        "action":"update-did-routes",
        "token":"'
                                           || vv_post_auth_tenant_token
                                           || '",
        "did-routes": 
        [
    ';
        IF ( instr(http_response, '"did-routes":[]') > 0 ) THEN
            json_parameter_update_did_route := concat(json_parameter_update_did_route, '{"uuid":'
                                                                                       || '"'
                                                                                       || vv_tenant_id
                                                                                       || '"'
                                                                                       || ',"pattern":"'
                                                                                       || vv_d_username
                                                                                       || '"}]}');
        ELSE
            FOR rec IN (
                SELECT
                    x.*
                FROM
                        JSON_TABLE ( http_response, '$'
                            COLUMNS (
                                NESTED PATH '$."did-routes"[*]'
                                    COLUMNS (
                                        uuid VARCHAR2 ( 100 ) PATH '$.uuid',
                                        patterns VARCHAR2 ( 100 ) PATH '$.pattern'
                                    )
                            )
                        )
                    x
            ) LOOP
                IF ( rec.patterns = vv_d_username ) THEN
                    vo_result := -4013;
                    vo_message := 'Error: DID route already exists';
                    pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user
                    , vv_exe_time);

                    dbms_output.put_line(TO_CHAR($$plsql_line)
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

                json_parameter_update_did_route := concat(json_parameter_update_did_route, '{"uuid":'
                                                                                           || '"'
                                                                                           || rec.uuid
                                                                                           || '"'
                                                                                           || ', "pattern":'
                                                                                           || '"'
                                                                                           || rec.patterns
                                                                                           || '"'
                                                                                           || '},');

            END LOOP;

            json_parameter_update_did_route := concat(json_parameter_update_did_route, '{"uuid":'
                                                                                       || '"'
                                                                                       || vv_tenant_id
                                                                                       || '"'
                                                                                       || ',"pattern":"'
                                                                                       || vv_d_username
                                                                                       || '"}]}');

        END IF;

        midware.mid_http_post(gv_http_tenant_url, json_parameter_update_did_route, 'application/json', http_status, http_response

        );
        IF ( instr(http_response, 'success') < 1 ) THEN
            vo_result := -4014;
            vo_message := 'Error: Unable to update DID route';
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );

            RETURN vo_result;
        END IF;

        vo_message := 'success';
        vo_result := 0;
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_add_did;

    FUNCTION fn_get_resource_plan_id (
        vi_username           VARCHAR2,
        vi_password           VARCHAR2,
        vi_ip_info            VARCHAR2,
        vi_plan_name          VARCHAR2,
        vo_resource_plan_id   OUT                   VARCHAR2,
        vo_message            OUT                   VARCHAR2,
        vo_result             OUT                   NUMBER
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

    --FUNCTION VARIABLES
        vv_http_url           VARCHAR2(1000);
        vv_http_parameter     VARCHAR2(1000);
        vv_http_status        VARCHAR2(50);
        vv_http_response      VARCHAR2(32767);
        vv_plan_name          VARCHAR2(50);
        vv_resource_plan_id   VARCHAR2(50);
        vv_message            VARCHAR(1000);
        vv_cnt                NUMBER(5, 0) := 0;

        --AUTHENTICATION VARIABLES
        auth_token            VARCHAR2(1000);
        auth_message          VARCHAR2(1000);
        auth_result           NUMBER;
        --END AUTHENTICATION VARIABLES
    --END FUNCTION VARIABLES
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        auth_result := pck_pbx.fn_post_authenticate_tenant('AIRVANTAGE', 'TEST', 'VI_IP_INFO', auth_token, auth_message, auth_result
        );
    --dbms_output.put_line(to_char($$plsql_line)||'|'||'AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);    

        IF ( auth_result = 0 ) THEN
            vv_http_url := pck_pbx.gv_http_tenant_url;
            vv_http_parameter := '{"action":"resource-plans",'
                                 || '"token":"'
                                 || auth_token
                                 || '"}';
            midware.mid_http_post(vv_http_url, vv_http_parameter, 'application/json', vv_http_status, vv_http_response);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_RESPONSE||'|'||VV_HTTP_STATUS);
            FOR rec IN (
                SELECT
                    x.status,
                    x.error,
                    x.id,
                    x.name
                FROM
                        JSON_TABLE ( vv_http_response, '$'
                            COLUMNS (
                                status VARCHAR ( 50 ) PATH '$.status',
                                error VARCHAR ( 50 ) PATH '$.error',
                                NESTED PATH '$.resource_plans[*]'
                                    COLUMNS (
                                        id VARCHAR2 ( 200 ) PATH '$.id',
                                        name VARCHAR2 ( 100 ) PATH '$.name'
                                    )
                            )
                        )
                    AS x
            ) LOOP IF ( rec.status = 'success' ) THEN
                IF ( vi_plan_name = rec.name ) THEN
                    vo_resource_plan_id := rec.id;
                --VO_PLAN_NAME:= rec.name;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_PLAN_NAME||'|'||VO_RESOURCE_PLAN_ID);
                    vv_cnt := vv_cnt + 1;
                    vo_result := 0;
                    vo_message := 'Successfully retrieved resource plan ID.';
                    EXIT;
                ELSE
                    vo_result := -2050;
                    vo_message := 'Error: Plan does not exist';
                END IF;

            ELSE
                vo_message := 'Error: Unable to query plan';
                vo_result := -4015;
                pck_middle.mid_log_execution(vv_sid, SYSDATE, vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                );

                RETURN vo_result;
            END IF;
            END LOOP;

        END IF;

        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_get_resource_plan_id;

    FUNCTION fn_get_resource_plan_nm (
        vi_username           VARCHAR2,
        vi_password           VARCHAR2,
        vi_ip_info            VARCHAR2,
        vi_resource_plan_id   VARCHAR2,
        vo_plan_nm            OUT                   VARCHAR2,
        vo_message            OUT                   VARCHAR2,
        vo_result             OUT                   NUMBER
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

    --FUNCTION VARIABLES
        vv_http_url           VARCHAR2(1000);
        vv_http_parameter     VARCHAR2(1000);
        vv_http_status        VARCHAR2(50);
        vv_http_response      VARCHAR2(32767);
        vv_plan_name          VARCHAR2(50);
        vv_resource_plan_id   VARCHAR2(50);
        vv_message            VARCHAR(1000);
        vv_cnt                NUMBER(5, 0) := 0;

        --AUTHENTICATION VARIABLES
        auth_token            VARCHAR2(1000);
        auth_message          VARCHAR2(1000);
        auth_result           NUMBER;
        --END AUTHENTICATION VARIABLES
    --END FUNCTION VARIABLES
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        auth_result := pck_pbx.fn_post_authenticate_tenant('AIRVANTAGE', 'TEST', 'VI_IP_INFO', auth_token, auth_message, auth_result
        );
    --dbms_output.put_line(to_char($$plsql_line)||'|'||'AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);    

        IF ( auth_result = 0 ) THEN
            vv_http_url := pck_pbx.gv_http_tenant_url;
            vv_http_parameter := '{"action":"resource-plans",'
                                 || '"token":"'
                                 || auth_token
                                 || '"}';
            midware.mid_http_post(vv_http_url, vv_http_parameter, 'application/json', vv_http_status, vv_http_response);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_RESPONSE||'|'||VV_HTTP_STATUS);
            FOR rec IN (
                SELECT
                    x.status,
                    x.error,
                    x.id,
                    x.name
                FROM
                        JSON_TABLE ( vv_http_response, '$'
                            COLUMNS (
                                status VARCHAR ( 50 ) PATH '$.status',
                                error VARCHAR ( 50 ) PATH '$.error',
                                NESTED PATH '$.resource_plans[*]'
                                    COLUMNS (
                                        id VARCHAR2 ( 200 ) PATH '$.id',
                                        name VARCHAR2 ( 100 ) PATH '$.name'
                                    )
                            )
                        )
                    AS x
            ) LOOP IF ( rec.status = 'success' ) THEN
                IF ( rec.id = vi_resource_plan_id ) THEN
                    vo_plan_nm := rec.name;
                --VO_PLAN_NAME:= rec.name;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_PLAN_NAME||'|'||VO_RESOURCE_PLAN_ID);
                    vv_cnt := vv_cnt + 1;
                    vo_result := 0;
                    vo_message := 'Successfully retrieved plan name';
                ELSE
                    vo_result := -2050;
                    vo_message := 'Error: Plan does not exist';
                END IF;

            ELSE
                vo_message := 'Error: Unable to query plan';
                vo_result := -4015;
                pck_middle.mid_log_execution(vv_sid, SYSDATE, vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                );

                RETURN vo_result;
            END IF;
            END LOOP;

        END IF;

        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_get_resource_plan_nm;

    FUNCTION fn_update_tenant (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vi_plan_name        VARCHAR2,
        vo_message          OUT                 VARCHAR2,
        vo_result           OUT                 NUMBER
    ) RETURN NUMBER AS

    --INTERFACE VARIABLES

        vv_mid_id_user            NUMBER := 1;
        vv_log_message            VARCHAR2(2000);
        vv_exe_time               NUMBER := dbms_utility.get_time;
        vv_sid                    NUMBER;
        vv_do_log                 CHAR;
        vv_name_interface         VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface           NUMBER;
        vv_id_codsystem           NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        vv_http_url               VARCHAR2(2000);
        vv_http_parameter         VARCHAR2(2000);
        vv_http_status            VARCHAR2(100);
        vv_http_response          VARCHAR2(32767);
        vv_tenant_resource_id     VARCHAR2(2000);
        vv_message                VARCHAR2(2000);
        vv_plan_name              VARCHAR2(50);

        --FUNCTION VARIABLES
        --AUTHENTICATION VARIABLES
        auth_token                VARCHAR2(1000);
        auth_message              VARCHAR2(1000);
        auth_result               NUMBER;
        --END AUTHENTICATION VARIABLES

        --FIND VARIABLES
        find_tenant_id            VARCHAR2(1000);
        find_message              VARCHAR2(1000);
        find_tenant_resource_id   VARCHAR2(1000);
        find_result               NUMBER;
        find_http_response        VARCHAR2(10000);
        find_http_parameter       VARCHAR2(1000);
        find_http_status          VARCHAR2(100);
        --END FIND VARIABLES

         --RESOURCE VARIABLES
        res_message               VARCHAR2(1000);
        res_resource_plan_id      VARCHAR2(1000);
        res_result                NUMBER;        
        --END RESOURCE VARIABLES

    --END FUNCTION VARIABLES
    BEGIN
        vv_plan_name := upper(vi_plan_name);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_PLAN_NAME);    
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
    /*
    IF REGEXP_LIKE(VI_T_USERNAME,'^[0-9]{7}$') AND (REGEXP_LIKE(VI_T_NEW_USERNAME,'^[0-9]{7}$') OR VI_T_NEW_USERNAME IS NULL) THEN
    */
        IF regexp_like(vi_t_username, '^[0-9]{7}$') AND ( vi_t_new_username IS NULL OR vi_t_new_username IS NOT NULL AND regexp_like
        (vi_t_new_username, '^[0-9]{7}$') ) THEN
            auth_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, auth_token, auth_message, auth_result
            );
    --dbms_output.put_line(to_char($$plsql_line)||'|'||AUTH_RESULT||'|'||AUTH_TOKEN||'|'||AUTH_MESSAGE);

            find_result := pck_pbx.fn_get_tenant_id(vi_username, vi_password, vi_ip_info, vi_t_username, find_tenant_id, find_tenant_resource_id

            , find_message, find_result);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_RESULT||'|'||FIND_TENANT_RESOURCE_ID||'|'||FIND_MESSAGE);

            res_result := pck_pbx.fn_get_resource_plan_id(vi_username, vi_password, vi_ip_info, vv_plan_name, res_resource_plan_id

            , res_message, res_result);
    --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESULT||'|'||RES_RESOURCE_PLAN_ID||'|'||RES_MESSAGE);

    --VV_HTTP_PARAMETER:= '{"action":"resource-plans",'||'"token":"'||AUTH_TOKEN||'"}';

            find_http_parameter := '{"action":"tenant", "id":"'
                                   || find_tenant_id
                                   || '",'
                                   || '"token":"'
                                   || auth_token
                                   || '"}';

            midware.mid_http_post(pck_pbx.gv_http_tenant_url, find_http_parameter, 'application/json', find_http_status, find_http_response

            );
    --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_HTTP_STATUS||'|'||FIND_HTTP_RESPONSE);
            SELECT
                JSON_VALUE(find_http_response, '$.status')
            INTO find_http_status
            FROM
                dual;
    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'FIND_HTTP_STATUS='||FIND_HTTP_STATUS);

            IF find_http_status = 'success' THEN
                IF ( vv_plan_name IS NULL ) THEN
                    vv_tenant_resource_id := find_tenant_resource_id;
                ELSE
                    vv_tenant_resource_id := res_resource_plan_id;
                END IF;

        --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_TENANT_RESOURCE_ID);

                IF ( ( vi_t_new_username IS NULL OR vi_t_username = vi_t_new_username ) AND find_tenant_resource_id != res_resource_plan_id /*OR VI_PLAN_NAME IS NOT NULL*/ ) THEN
        --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID);
                    find_http_response := substr(find_http_response, instr(find_http_response, '"owner"'));
                    find_http_response := substr(find_http_response, 1, length(find_http_response) - 1);
                    IF ( vv_tenant_resource_id IS NOT NULL ) THEN
                        find_http_response := replace(find_http_response, find_tenant_resource_id, vv_tenant_resource_id);
                --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID);
                        vv_http_parameter := '{"action":"update-tenant","id":"'
                                             || find_tenant_id
                                             || '","token":"'
                                             || auth_token
                                             || '",'
                                             || find_http_response;
            --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_PARAMETER);

                        vv_http_url := pck_pbx.gv_http_tenant_url;
                        midware.mid_http_post(vv_http_url, vv_http_parameter, 'application/json', vv_http_status, vv_http_response
                        );
                        SELECT
                            JSON_VALUE(vv_http_response, '$.status')
                        INTO vv_http_status
                        FROM
                            dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_HTTP_STATUS='||VV_HTTP_STATUS);

                        IF vv_http_status = 'pending' THEN
                            SELECT
                                'Tenant is being updated.'
                            INTO vv_message
                            FROM
                                dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);

                            vo_message := vv_message;
                            vo_result := 0;
                        ELSE
                            SELECT
                                JSON_VALUE(vv_http_response, '$.error')
                            INTO vv_message
                            FROM
                                dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);

                            vo_result := -4016;
                            vo_message := 'Error: Unable to update tenant';
                            RETURN vo_result;
                        END IF;

                    ELSE
                        vo_message := res_message;
                        vo_result := res_result;
                    END IF;

                ELSIF ( ( vi_t_new_username IS NULL OR vi_t_username = vi_t_new_username ) AND ( find_tenant_resource_id = res_resource_plan_id

                OR vv_plan_name IS NULL ) ) THEN
                    SELECT
                        'Error: New username or plan must be entered'
                    INTO vv_message
                    FROM
                        dual;

                    vo_message := vv_message;
                    vo_result := -2002;
                ELSE
                --dbms_output.put_line(to_char($$plsql_line)||'|'||RES_RESOURCE_PLAN_ID||'|'||VV_TENANT_RESOURCE_ID);
                    find_http_response := substr(find_http_response, instr(find_http_response, '"owner"'));
                    find_http_response := substr(find_http_response, 1, length(find_http_response) - 1);
                    IF ( vi_t_new_username IS NOT NULL ) THEN
                        find_http_response := replace(find_http_response, vi_t_username, vi_t_new_username);
                    END IF;

                    IF ( vv_tenant_resource_id IS NOT NULL ) THEN
                        find_http_response := replace(find_http_response, find_tenant_resource_id, vv_tenant_resource_id);

                --dbms_output.put_line(to_char($$plsql_line)||'|'||FIND_HTTP_RESPONSE);
                        vv_http_parameter := '{"action":"update-tenant","id":"'
                                             || find_tenant_id
                                             || '","token":"'
                                             || auth_token
                                             || '",'
                                             || find_http_response;
                --dbms_output.put_line(to_char($$plsql_line)||'|'||VV_HTTP_PARAMETER);

                        vv_http_url := pck_pbx.gv_http_tenant_url;
                        midware.mid_http_post(vv_http_url, vv_http_parameter, 'application/json', vv_http_status, vv_http_response
                        );
                        SELECT
                            JSON_VALUE(vv_http_response, '$.status')
                        INTO vv_http_status
                        FROM
                            dual;
                --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_HTTP_STATUS='||VV_HTTP_STATUS);

                        IF vv_http_status = 'pending' THEN
                            SELECT
                                'Tenant is being updated.'
                            INTO vv_message
                            FROM
                                dual;
                    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);

                            vo_message := vv_message;
                            vo_result := 0;
                        ELSE
                            SELECT
                                JSON_VALUE(vv_http_response, '$.error')
                            INTO vv_message
                            FROM
                                dual;
                    --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_MESSAGE='||VV_MESSAGE);

                            vo_result := -4016;
                            vo_message := 'Error: Unable to update tenant';
                            RETURN vo_result;
                        END IF;

                    ELSE
                        vo_message := res_message;
                        vo_result := res_result;
                    END IF;

                END IF;

            ELSE
                vo_result := find_result;
                vo_message := find_message;
                RETURN vo_result;
            END IF;

        ELSE
            SELECT
                'Error: Trunk must be 7 digit numeric value'
            INTO vv_message
            FROM
                dual;

            vo_message := vv_message;
            vo_result := -2001;
        END IF;

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_update_tenant;

    FUNCTION fn_delete_tenant (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER IS

--INTERFACE VARIABLES

        vv_mid_id_user                 NUMBER := 1;
        vv_log_message                 VARCHAR2(2000);
        vv_exe_time                    NUMBER := dbms_utility.get_time;
        vv_sid                         NUMBER;
        vv_do_log                      CHAR;
        vv_name_interface              VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                NUMBER;
        vv_id_codsystem                NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                    VARCHAR2(3);
        http_url                       VARCHAR(1000);
        http_parameter                 VARCHAR2(1000);
        http_response                  VARCHAR2(12000);
        json_get_did_routes            VARCHAR2(1000);
        json_parameter_delete_tenant   VARCHAR2(1000);
        vv_post_auth_tenant_token      VARCHAR2(1000);
        vv_post_auth_tenant_message    VARCHAR2(1000);
        vv_post_auth_tenant_result     INT;
        vv_tenant_id_result            NUMBER;
        vv_tenant_id_message           VARCHAR2(100);
        vv_tenant_id                   VARCHAR2(100);
    --vv_d_username                   VARCHAR2(100) := '+501'||vi_did_number;
        vv_tenant_resource_id          VARCHAR2(100);

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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA


  --NUMERIC VALIDATION
        IF NOT regexp_like(vi_t_username, '^[0-9]{7}$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -2001;
            RETURN vo_result;
        END IF;

        vv_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vv_post_auth_tenant_token

        , vv_post_auth_tenant_message, vv_post_auth_tenant_result);

        IF ( vv_post_auth_tenant_result < 0 ) THEN
            vo_result := vv_post_auth_tenant_result;
            vo_message := vv_post_auth_tenant_message;
            RETURN vo_result;
        END IF;

        vv_tenant_id_result := pck_pbx.fn_get_tenant_id(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id

        , vv_tenant_id_message, vv_tenant_id_result);

        dbms_output.put_line(vv_tenant_id);
        IF ( vv_tenant_id_result < 0 ) THEN
            vo_result := vv_tenant_id_result;
            vo_message := vv_tenant_id_message;
            RETURN vo_result;
        END IF;

        json_parameter_delete_tenant := '
    {
        "action":"delete-tenant",
        "id":"'
                                        || vv_tenant_id
                                        || '",
        "token":"'
                                        || vv_post_auth_tenant_token
                                        || '"}';
        midware.mid_http_post(gv_http_tenant_url, json_parameter_delete_tenant, 'application/json', http_status, http_response);
        dbms_output.put_line(http_response);
        IF ( instr(http_response, 'pending') < 1 ) THEN
            vo_result := -4019;
            vo_message := 'Error: Unable to delete tenant';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        vo_message := 'success';
        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_delete_tenant;

    FUNCTION fn_delete_did (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_did_number   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER IS

--INTERFACE VARIABLES

        vv_mid_id_user                    NUMBER := 1;
        vv_log_message                    VARCHAR2(2000);
        vv_exe_time                       NUMBER := dbms_utility.get_time;
        vv_sid                            NUMBER;
        vv_do_log                         CHAR;
        vv_name_interface                 VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                   NUMBER;
        vv_id_codsystem                   NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                       VARCHAR2(3);
        http_url                          VARCHAR(1000);
        http_parameter                    VARCHAR2(1000);
        http_response                     VARCHAR2(12000);
        json_get_did_routes               VARCHAR2(1000);
        json_parameter_update_did_route   VARCHAR2(1000);
        vv_post_auth_tenant_token         VARCHAR2(1000);
        vv_post_auth_tenant_message       VARCHAR2(1000);
        vv_post_auth_tenant_result        INT;
        vv_tenant_id_result               NUMBER;
        vv_tenant_id_message              VARCHAR2(100);
        vv_tenant_id                      VARCHAR2(100);
        vv_d_username                     VARCHAR2(100) := '+501' || vi_did_number;
        vv_tenant_resource_id             VARCHAR2(100);
        vv_did_found                      INT;
        vv_count                          INT;

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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;

--END INTERFACE DATA
        vv_did_found := 0;
        vv_count := 0;
        vv_post_auth_tenant_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vv_post_auth_tenant_token
        , vv_post_auth_tenant_message, vv_post_auth_tenant_result);

        IF ( vv_post_auth_tenant_result < 0 ) THEN
            vo_result := vv_post_auth_tenant_result;
            vo_message := vv_post_auth_tenant_message;
            RETURN vo_result;
        END IF;

        vv_tenant_id_result := pck_pbx.fn_get_tenant_id(vi_username, vi_password, vi_ip_info, vi_t_username, vv_tenant_id, vv_tenant_resource_id

        , vv_tenant_id_message, vv_tenant_id_result);

        IF ( vv_tenant_id_result < 0 ) THEN
            vo_result := vv_tenant_id_result;
            vo_message := vv_tenant_id_message;
            RETURN vo_result;
        END IF;

        json_get_did_routes := '
        {
            "action":"did-routes",
            "token":"'
                               || vv_post_auth_tenant_token
                               || '"
        }
    ';
        midware.mid_http_post(gv_http_tenant_url, json_get_did_routes, 'application/json', http_status, http_response);
        IF ( instr(http_response, 'success') < 1 ) THEN
            vo_result := -4017;
            vo_message := 'Error: Unable to query DID routes';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        json_parameter_update_did_route := '
    {
        "action":"update-did-routes",
        "token":"'
                                           || vv_post_auth_tenant_token
                                           || '",
        "did-routes": 
        [
    ';

    /*
    IF ( instr(http_response, '"did-routes":[]') > 0 ) THEN

        json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||vv_tenant_id||'"'||',"pattern":"'||vv_d_username||'"}]}');

    ELSE*/
        FOR rec IN (
            SELECT
                x.*
            FROM
                    JSON_TABLE ( http_response, '$'
                        COLUMNS (
                            NESTED PATH '$."did-routes"[*]'
                                COLUMNS (
                                    uuid VARCHAR2 ( 100 ) PATH '$.uuid',
                                    patterns VARCHAR2 ( 100 ) PATH '$.pattern'
                                )
                        )
                    )
                x
        ) LOOP
            IF ( rec.patterns = vv_d_username ) THEN
                vv_did_found := 1;
            ELSE 
                --json_parameter_update_did_route := CONCAT(json_parameter_update_did_route, '{"uuid":'||'"'||rec.uuid||'"' || ', "pattern":' ||'"'||rec.patterns||'"'||'},');
                IF vv_count = 0 THEN
                    json_parameter_update_did_route := concat(json_parameter_update_did_route, '{"uuid":'
                                                                                               || '"'
                                                                                               || rec.uuid
                                                                                               || '"'
                                                                                               || ', "pattern":'
                                                                                               || '"'
                                                                                               || rec.patterns
                                                                                               || '"'
                                                                                               || '}');

                ELSE
                    json_parameter_update_did_route := concat(json_parameter_update_did_route, ',{"uuid":'
                                                                                               || '"'
                                                                                               || rec.uuid
                                                                                               || '"'
                                                                                               || ', "pattern":'
                                                                                               || '"'
                                                                                               || rec.patterns
                                                                                               || '"'
                                                                                               || '}');
                END IF;
            END IF;

            vv_count := vv_count + 1;
        END LOOP;

        json_parameter_update_did_route := concat(json_parameter_update_did_route, ']}');
        IF vv_did_found != 1 THEN
            vo_result := -2050;
            vo_message := 'Error: DID route not found';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        midware.mid_http_post(gv_http_tenant_url, json_parameter_update_did_route, 'application/json', http_status, http_response

        );
        dbms_output.put_line(json_parameter_update_did_route);
        IF ( instr(http_response, 'success') < 1 ) THEN
            vo_result := -4018;
            vo_message := 'Error: Unable to delete DID route';
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF;

        vo_message := 'success';
        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_delete_did;

    FUNCTION fn_find_trunk (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_product      VARCHAR2,
        vo_trunk_id     OUT             NUMBER,
        vo_t_username   OUT             VARCHAR2,
        vo_t_password   OUT             VARCHAR2,
        vo_result       OUT             NUMBER,
        vo_message      OUT             VARCHAR2
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user          NUMBER := 1;
        vv_log_message          VARCHAR2(2000);
        vv_exe_time             NUMBER := dbms_utility.get_time;
        vv_sid                  NUMBER;
        vv_do_log               CHAR;
        vv_name_interface       VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface         NUMBER;
        vv_id_codsystem         NUMBER;
--END INTERFACE VARIABLES
        http_status             VARCHAR2(3);
    --http_url_authenticate    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/authenticate';
        http_url_authenticate   VARCHAR(100) := 'https://'
                                              || 'PBX-'
                                              || vi_t_username
                                              || '.'
                                              || gv_http_url
                                              || '/authenticate';
    --http_url_find_trunk    VARCHAR(100) := 'https://devtest.'||gv_http_url||'/find_trunk';
        http_url_find_trunk     VARCHAR(100) := 'https://'
                                            || 'PBX-'
                                            || vi_t_username
                                            || '.'
                                            || gv_http_url
                                            || '/find_trunk';
        http_url                VARCHAR(1000);
        http_parameter          VARCHAR2(1000);
        http_response           VARCHAR2(12000);
        vo_post_auth_result     INT;
        vo_post_auth_message    VARCHAR2(1000);
        vo_post_auth_token      VARCHAR2(1000);
        vv_trunk_id             NUMBER;
        vv_t_username           VARCHAR2(25);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
--END INTERFACE DATA
        vo_post_auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username, vo_post_auth_message
        , vo_post_auth_token, vo_post_auth_result);

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
                SELECT
                    JSON_VALUE(http_response, '$.data.trunk_id')
                INTO vo_trunk_id
                FROM
                    dual;

                SELECT
                    JSON_VALUE(http_response, '$.data.outgoing_username')
                INTO vo_t_username
                FROM
                    dual;

                SELECT
                    JSON_VALUE(http_response, '$.data.outgoing_remotesecret')
                INTO vo_t_password
                FROM
                    dual;

                vo_t_username := ltrim(vo_t_username, '+501');
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            ELSIF ( instr(http_response, '"data":[]') >= 1 ) THEN
        -- "data":[]
                vo_result := -2050;
                vo_message := 'Error: Trunk not found';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            ELSE
                vo_result := -5011;
                vo_message := 'Error: Unable to query trunk';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            END IF;

        END IF;

        vo_result := -5000;
        vo_message := 'Error: Tenant Authentication Unsuccessful';
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_find_trunk;

    FUNCTION fn_update_subscriber (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vi_t_new_password   VARCHAR2,
        vi_product          IN                  VARCHAR2,
        vo_result           OUT                 NUMBER,
        vo_message          OUT                 VARCHAR2
    ) RETURN NUMBER AS
    --INTERFACE VARIABLES

        vv_mid_id_user        NUMBER := 1;
        vv_log_message        VARCHAR2(2000);
        vv_exe_time           NUMBER := dbms_utility.get_time;
        vv_sid                NUMBER;
        vv_do_log             CHAR;
        vv_name_interface     VARCHAR2(24) := utl_call_stack.subprogram(1)(2);
        vv_id_interface       NUMBER;
        vv_id_codsystem       NUMBER;
    --END INTERFACE VARIABLES

    --FUNCTION VARIABLES
        vv_message            VARCHAR2(1000);
        --AUTHENTICATION VARIABLES
        auth_http_url         VARCHAR2(2000);
        auth_http_parameter   VARCHAR2(2000);
        auth_token            VARCHAR2(1000);
        auth_message          VARCHAR2(1000);
        auth_result           NUMBER;
        --FIND_TRUNK VARIABLES
        find_http_url         VARCHAR2(2000);
        find_http_parameter   VARCHAR2(2000);
        find_http_message     VARCHAR2(2000);
        find_result           NUMBER;
        find_trunk_id         NUMBER;
        find_t_username       VARCHAR2(100);
        find_product          VARCHAR2(100);
        --UPDATE_TRUNK VARIABLES
        upd_http_url          VARCHAR2(2000);
        upd_http_parameter    VARCHAR2(2000);
        upd_http_response     VARCHAR2(2000);
        upd_message           VARCHAR2(1000);
        upd_result            VARCHAR2(1000);
        upd_status            VARCHAR2(1000);
        --UPDATE_U2000 VARIABLES
        upd_u2000_result      NUMBER;
        upd_u2000_message     VARCHAR2(1000);
        find_t_password       VARCHAR2(100);

    --END FUNCTION VARIABLES
        gv_codsystem          VARCHAR2(20) := 'HOSTED';
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        IF regexp_like(vi_t_username, '^[0-9]{7}$') AND ( vi_t_new_username IS NULL OR vi_t_new_username IS NOT NULL AND regexp_like
        (vi_t_new_username, '^[0-9]{7}$') ) THEN
            vo_message := NULL;
    --AUTH_HTTP_URL      :=VI_TENANT_URL;
    --AUTH_HTTP_PARAMETER:=VI_API_KEY;
            auth_result := pck_pbx.fn_post_authenticate(vi_username, vi_password, vi_ip_info, vi_t_username, auth_token, auth_message
            , auth_result);
    --dbms_output.PUT_LINE('AUTH_RESULT='||AUTH_RESULT||'|'||'AUTH_MESSAGE='||AUTH_MESSAGE||'|'||'AUTH_TOKEN='||AUTH_TOKEN);

            vo_message := auth_message;
            find_result := pck_pbx.fn_find_trunk(vi_username, vi_password, vi_ip_info, vi_t_username, find_product, find_trunk_id
            , find_t_username, find_t_password, find_result, find_http_message);
    --dbms_output.PUT_LINE('FIND_TRUNK_ID='||FIND_TRUNK_ID||'|'||'FIND_HTTP_MESSAGE='||FIND_HTTP_MESSAGE);

            vo_message := find_http_message;
            IF ( find_trunk_id >= 1 ) THEN
                vo_result := 0;
                IF ( ( vi_t_new_username IS NULL OR vi_t_username = vi_t_new_username ) AND vi_t_new_password IS NOT NULL ) THEN
                    upd_http_parameter := 'token='
                                          || auth_token
                                          || '&outgoing_remotesecret='
                                          || vi_t_new_password;
                ELSIF ( vi_t_username != vi_t_new_username ) THEN
                    IF vi_t_new_password IS NULL THEN
                        upd_http_parameter := 'token='
                                              || auth_token
                                              || '&description=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_username=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_defaultuser=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_fromuser=%2B501'
                                              || vi_t_new_username
                                              || '&trunk_cid=%22%22%20%3C%2B501'
                                              || vi_t_new_username
                                              || '%3E'
                                              || '&outgoing_remotesecret='
                                              || find_t_password
                                              || '&register=%2B501'
                                              || vi_t_new_username
                                              || '%40'
                                              || gv_outgoing_host
                                              || '---mtob-'
                                              || gv_outbound_proxy
                                              || '%3A'
                                              || find_t_password
                                              || '%3A%2B501'
                                              || vi_t_new_username
                                              || '%40'
                                              || gv_outgoing_host
                                              || '%40'
                                              || gv_outbound_proxy
                                              || '%3A'
                                              || gv_outgoing_port
                                              || '%2F%2B501'
                                              || vi_t_new_username;

                    ELSE
                        upd_http_parameter := 'token='
                                              || auth_token
                                              || '&description=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_username=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_defaultuser=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_fromuser=%2B501'
                                              || vi_t_new_username
                                              || '&outgoing_remotesecret='
                                              || vi_t_new_password
                                              || '&trunk_cid=%22%22%20%3C%2B501'
                                              || vi_t_new_username
                                              || '%3E'
                                              || '&register=%2B501'
                                              || vi_t_new_username
                                              || '%40'
                                              || gv_outgoing_host
                                              || '---mtob-'
                                              || gv_outbound_proxy
                                              || '%3A'
                                              || vi_t_new_password
                                              || '%3A%2B501'
                                              || vi_t_new_username
                                              || '%40'
                                              || gv_outgoing_host
                                              || '%40'
                                              || gv_outbound_proxy
                                              || '%3A'
                                              || gv_outgoing_port
                                              || '%2F%2B501'
                                              || vi_t_new_username;
                    END IF;
                ELSE
                    RETURN 0;
                END IF;

                upd_http_url := 'https://'
                                || 'PBX-'
                                || vi_t_username
                                || '.'
                                || pck_pbx.gv_http_url
                                || '/modify_trunk/'
                                || find_trunk_id;

                midware.test_http_post(upd_http_url, upd_http_parameter, upd_result, upd_http_response);
                SELECT
                    JSON_VALUE(upd_http_response, '$.status')
                INTO upd_status
                FROM
                    dual;
        --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VV_STATUS='||VV_STATUS);

                IF upd_status = 'success' THEN
                    SELECT
                        'Trunk ID '
                        || find_trunk_id
                        || ' was succesfully updated.'
                    INTO upd_message
                    FROM
                        dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_MESSAGE='||UPD_MESSAGE);

                    vo_message := upd_message;
                ELSE
                    SELECT
                        JSON_VALUE(upd_http_response, '$.message')
                    INTO upd_message
                    FROM
                        dual;
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_MESSAGE='||UPD_MESSAGE);

                    vo_result := -5012;
                    vo_message := 'Error: Unable to update trunk';
                    RETURN vo_result;
                END IF;
        --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'VO_RESULT='||VO_RESULT);

                IF vo_result = 0 THEN
                    upd_u2000_result := pck_pbx.fn_update_trunk_u2000_middb(vi_username, vi_password, vi_ip_info, vi_t_username, vi_t_new_username
                    , upd_u2000_result, upd_u2000_message);
            --dbms_output.PUT_LINE(to_char($$plsql_line)|| ': '||'UPD_U2000_RESULT='||UPD_U2000_RESULT);
                ELSE
                    RETURN 0;
                END IF;

                IF vo_result != upd_u2000_result THEN
                    vo_message := 'Partial Success: '
                                  || upd_message
                                  || ' '
                                  || upd_u2000_message;
                    vo_result := -6000;
                END IF;

            END IF;

        ELSE
            SELECT
                'USERNAME NEEDS TO BE NUMERIC AND 7 DIGITS LONG.'
            INTO vv_message
            FROM
                dual;

            vo_message := vv_message;
            vo_result := -1001;
        END IF;

        vo_result := 0;
        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_update_subscriber;

    FUNCTION fn_update_trunk_u2000_middb (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vo_result           OUT                 NUMBER,
        vo_message          OUT                 VARCHAR2
    ) RETURN NUMBER AS

    --INTERFACE VARIABLES

        vv_mid_id_user      NUMBER := 1;
        vv_log_message      VARCHAR2(2000);
        vv_exe_time         NUMBER := dbms_utility.get_time;
        vv_sid              NUMBER;
        vv_do_log           CHAR;
        vv_name_interface   VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface     NUMBER;
        vv_id_codsystem     NUMBER;
    --END INTERFACE VARIABLES
        upd_pbx_id          NUMBER;
        get_result          NUMBER;
        get_message         VARCHAR2(400);
        upd_result          VARCHAR2(400);
        upd_trunk           NUMBER;
        upd_cdate           VARCHAR2(400);
        cnt                 NUMBER;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        SELECT
            COUNT(hosted.pbx_id)
        INTO cnt
        FROM
            midware.hosted_pbx_u2000 hosted
        WHERE
            vi_t_username = phone_num
            AND deleted_at IS NULL;

        dbms_output.put_line(TO_CHAR($$plsql_line)
                             || 'counter'
                             || '|'
                             || cnt);

        IF cnt > 1 THEN
            vo_result := -2200;
            vo_message := 'Fetch returns more than 1 active instance on the number ' || vi_t_username;
        END IF;

        IF cnt = 1 THEN
            get_result := pck_pbx.fn_get_trunk_u2000(vi_username, vi_password, vi_ip_info, vi_t_username, get_message, get_result
            );
        --dbms_output.PUT_LINE(to_char($$plsql_line)||'GET_RESULT'||'|'||GET_RESULT);       

            IF get_result = 0 THEN
                SELECT
                    pbx_id
                INTO upd_pbx_id
                FROM
                    midware.hosted_pbx_u2000
                WHERE
                    vi_t_username = phone_num
                    AND deleted_at IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_PBX_ID'||'|'||UPD_PBX_ID);

                SELECT
                    created_at
                INTO upd_cdate
                FROM
                    midware.hosted_pbx_u2000
                WHERE
                    vi_t_username = phone_num
                    AND deleted_at IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_CDATE'||'|'||UPD_CDATE);

                SELECT
                    trunk_id
                INTO upd_trunk
                FROM
                    midware.hosted_pbx_u2000
                WHERE
                    vi_t_username = phone_num
                    AND deleted_at IS NULL;
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'UPD_TRUNK'||'|'||UPD_TRUNK);

                upd_result := pck_pbx.fn_ssh_connect(gv_update_u2000
                                                     || ' '
                                                     || vi_t_new_username
                                                     || ' '
                                                     || upd_trunk);
            --dbms_output.PUT_LINE(to_char($$plsql_line)||'|'||UPD_RESULT);

                IF upd_result = 'SUCCESS' THEN
                    UPDATE midware.hosted_pbx_u2000
                    SET
                        deleted_at = SYSDATE
                    WHERE
                        upd_pbx_id = pbx_id;

                    INSERT INTO midware.hosted_pbx_u2000 (
                        trunk_id,
                        route_id,
                        sub_route_id,
                        phone_num,
                        created_at,
                        updated_at,
                        deleted_at
                    ) VALUES (
                        upd_trunk,
                        upd_trunk,
                        upd_trunk,
                        vi_t_new_username,
                        upd_cdate,
                        SYSDATE,
                        NULL
                    );

                ELSE
                    vo_result := -3000;
                    vo_message := upd_result;
                END IF;

            ELSE
                vo_result := get_result;
                vo_message := get_message;
            END IF;

            vo_result := 0;
            vo_message := 'The number '
                          || vi_t_username
                          || ' was changed to '
                          || vi_t_new_username
                          || '.';
        ELSIF cnt = 0 THEN
            vo_result := -2100;
            vo_message := 'The number '
                          || vi_t_username
                          || ' does not exists in HOSTED_PBX_U2000 Table.';
        END IF;

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_update_trunk_u2000_middb;

    FUNCTION fn_get_trunk_u2000 (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER IS

--INTERFACE VARIABLES

        vv_mid_id_user                    NUMBER := 1;
        vv_log_message                    VARCHAR2(2000);
        vv_exe_time                       NUMBER := dbms_utility.get_time;
        vv_sid                            NUMBER;
        vv_do_log                         CHAR;
        vv_name_interface                 VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface                   NUMBER;
        vv_id_codsystem                   NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
        trunk_id                          NUMBER;
        json_get_did_routes               VARCHAR2(1000);
        json_parameter_update_did_route   VARCHAR2(1000);
        ssh_message                       VARCHAR2(100);
        ssh_result                        NUMBER;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;

--END INTERFACE DATA
        BEGIN
            SELECT
                hosted.trunk_id
            INTO trunk_id
            FROM
                midware.hosted_pbx_u2000 hosted
            WHERE
                hosted.phone_num = vi_t_username
                AND hosted.deleted_at IS NULL;

        EXCEPTION
            WHEN no_data_found THEN
                RAISE no_data_found;
        END;

        ssh_message := pck_pbx.fn_ssh_connect(gv_get_u2000
                                              || ' '
                                              || trunk_id);
        ssh_result := regexp_replace(ssh_message, '[^[:digit:]]', '');
        IF ( ssh_result > 0 ) THEN
            vo_message := regexp_replace(ssh_message, '[^a-z and ^A-Z]', '');
            vo_result := ssh_result;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
--END Execute MID Log Execution

            RETURN vo_result;
        END IF;

        vo_message := 'success';
        vo_result := 0;
        dbms_output.put_line(TO_CHAR($$plsql_line)
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
--Execute MID Log Execution

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );
--END Execute MID Log Execution      

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN no_data_found THEN
            vo_result := -2100;
            vo_message := sqlerrm;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := sqlerrm;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_get_trunk_u2000;

    FUNCTION fn_add_trunk_u2000 (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER IS

--INTERFACE VARIABLES

        vv_mid_id_user      NUMBER := 1;
        vv_log_message      VARCHAR2(2000);
        vv_exe_time         NUMBER := dbms_utility.get_time;
        vv_sid              NUMBER;
        vv_do_log           CHAR;
        vv_name_interface   VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface     NUMBER;
        vv_id_codsystem     NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
        get_trunk_result    NUMBER;
        get_trunk_message   VARCHAR(50);
        add_trunk_result    NUMBER;
        add_trunk_message   VARCHAR(50);
        get_max_trunk_id    NUMBER;
        ssh_message         VARCHAR2(50);
        ssh_result          NUMBER;
        count_pbx_table     NUMBER;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;

--END INTERFACE DATA
        SELECT
            COUNT(hosted.trunk_id)
        INTO count_pbx_table
        FROM
            midware.hosted_pbx_u2000 hosted
        WHERE
            hosted.phone_num = vi_t_username
            AND hosted.deleted_at IS NULL;

        IF ( count_pbx_table = 1 ) THEN
            vo_message := 'error: Unable to add phone number '
                          || vi_t_username
                          || ' already exist in the Midware U2000 Table';
            vo_result := -2300;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
        --Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
        --END Execute MID Log Execution  

            RETURN vo_result;
        END IF;

        SELECT
            MAX(hosted.trunk_id)
        INTO get_max_trunk_id
        FROM
            midware.hosted_pbx_u2000 hosted;

        get_max_trunk_id := get_max_trunk_id + 1;
        INSERT INTO midware.hosted_pbx_u2000 (
            trunk_id,
            route_id,
            sub_route_id,
            phone_num,
            created_at,
            updated_at,
            deleted_at
        ) VALUES (
            get_max_trunk_id,
            get_max_trunk_id,
            get_max_trunk_id,
            vi_t_username,
            SYSDATE,
            NULL,
            NULL
        );

        get_trunk_result := pck_pbx.fn_get_trunk_u2000(vi_username, vi_password, vi_ip_info, vi_t_username, get_trunk_message, get_trunk_result

        );

        IF ( get_trunk_result = -2100 ) THEN
            ROLLBACK;
            vo_message := 'error: '
                          || 'No data found. Please verify if '
                          || vi_t_username
                          || ' exist in the Midware U2000 Table';
            vo_result := get_trunk_result;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
        --Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
        --END Execute MID Log Execution  

            RETURN vo_result;
        ELSIF ( get_trunk_result = 0 ) THEN
            ROLLBACK;
            vo_message := 'error: '
                          || 'ID exist on the U2000 Node.  Please verify ID Number '
                          || get_max_trunk_id
                          || ' on U2000 Node or Midware U2000 Table';
            vo_result := -2200;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
        --Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
        --END Execute MID Log Execution  

            RETURN vo_result;
        ELSIF ( get_trunk_result != 21 ) THEN
            ROLLBACK;
            vo_message := 'error: ' || get_trunk_message;
            vo_result := get_trunk_result;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
        --Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
        --END Execute MID Log Execution  

            RETURN vo_result;
        END IF;

        ssh_message := pck_pbx.fn_ssh_connect('add_telnet_1.sh '
                                              || vi_t_username
                                              || ' '
                                              || get_max_trunk_id);

        ssh_result := regexp_replace(ssh_message, '[^[:digit:]]', '');
        IF ( ssh_result > 0 ) THEN
            ROLLBACK;
            vo_message := regexp_replace(ssh_message, '[^a-z and ^A-Z]', '');
            vo_result := ssh_result;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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
        --Execute MID Log Execution

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );
        --END Execute MID Log Execution

            RETURN vo_result;
        END IF;

        COMMIT;
        vo_message := 'success';
        vo_result := 0;
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

--Execute MID Log Execution

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );
--END Execute MID Log Execution    

        RETURN vo_result;

    --When any errors then it logs the error
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            vo_result := -8000;
            vo_message := sqlerrm;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, 'ERROR '
                                                          || vi_ip_info
                                                          || ':'
                                                          || vo_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
                                                          );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            dbms_output.put_line(TO_CHAR($$plsql_line)
                                 || ': '
                                 || dbms_utility.format_error_stack
                                 || dbms_utility.format_call_stack
                                 || dbms_utility.format_error_backtrace); --TO DO: Log error with session call

            RETURN vo_result;
    END fn_add_trunk_u2000;

    FUNCTION fn_reconnect_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

 --FUNCTION VARIABLES

        vv_http_url                 VARCHAR2(2000);
        vv_http_parameter           VARCHAR2(2000);
        vv_cnt                      NUMBER := 0;
        vv_tenants                  VARCHAR2(1000);
        vv_http_status              VARCHAR2(100);
        vv_http_response            VARCHAR2(30000);
        pbx_number                  VARCHAR2(200) := 'PBX-' || vi_t_username;
 --END FUNCTION VARIABLES

 --INTERFACE VARIABLES
        vv_mid_id_user              NUMBER := 1;
        vv_log_message              VARCHAR2(3000);
        vv_exe_time                 NUMBER := dbms_utility.get_time;
        vv_sid                      NUMBER;
        vv_do_log                   CHAR;
        vv_name_interface           VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface             NUMBER;
        vv_id_codsystem             NUMBER;
--END INTERFACE VARIABLES

--PROGRAM VARIABLES
        http_status                 VARCHAR2(3);
        http_url                    VARCHAR(1000);
        http_parameter              VARCHAR2(1000);
        http_response               VARCHAR2(12000);
        vo_post_auth_token          VARCHAR2(1000);
        vo_post_auth_message        VARCHAR2(1000);
        vo_post_auth_result         INT;
        get_tenant_id_message       VARCHAR2(1000);
        get_tenant_id_result        NUMBER;
        get_tenant_id_tenant_id     VARCHAR2(100);
        get_tenant_id_resource_id   VARCHAR2(100);
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA

--NUMERIC VALIDATION
        IF NOT regexp_like(vi_t_username, '^[0-9]{7}$') THEN
            vo_message := 'Error: Trunk must be 7 digit numeric value';
            vo_result := -1021;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            RETURN vo_result;
        END IF; 
--END NUMERIC VALIDATION

        get_tenant_id_result := pck_pbx.fn_get_tenant_id(vi_username, vi_password, vi_ip_info, vi_t_username, get_tenant_id_tenant_id

        , get_tenant_id_resource_id, get_tenant_id_message, get_tenant_id_result);

        IF ( get_tenant_id_result != 0 ) THEN
            vo_message := get_tenant_id_message;
            vo_result := get_tenant_id_result;
            dbms_output.put_line(TO_CHAR($$plsql_line)
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

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

            );

            RETURN vo_result;
        END IF;

        vo_post_auth_result := pck_pbx.fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, vo_post_auth_token, vo_post_auth_message

        , vo_post_auth_result);

        IF ( vo_post_auth_result = 0 ) THEN
            http_parameter := '
        {
            "action":"start-tenant",
            "token":"'
                              || vo_post_auth_token
                              || '",
            "id":"'
                              || get_tenant_id_tenant_id
                              || '"         
        }';

        /*Removed as no longer necessary  "whitelist": [{"address":"172.21.56.33", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]},{"address":"172.21.56.30", "description":"authorized access", "services":["SSH","AMI","SIP","Web"]}]*/
            midware.mid_http_post(gv_http_tenant_url, http_parameter, 'application/json', http_status, http_response);
            IF ( instr(http_response, 'pending') >= 1 ) THEN
                vo_result := 0;
                vo_message := 'success';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            ELSIF ( instr(http_response, 'success') >= 1 ) THEN
                vo_result := -2042;
                vo_message := 'error: Tenant already active';
                dbms_output.put_line(TO_CHAR($$plsql_line)
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

                pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

                );

                RETURN vo_result;
            END IF;

        END IF;

        vo_result := -2010;
        vo_message := 'Error: Tenant Authentication Unssuccessful';
        dbms_output.put_line(TO_CHAR($$plsql_line)
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

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

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
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_reconnect_subscriber;

    FUNCTION fn_delete_trunk_u2000 (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             INT
    ) RETURN NUMBER AS

--INTERFACE VARIABLES

        vv_mid_id_user      NUMBER := 1;
        vv_log_message      VARCHAR2(2000);
        vv_exe_time         NUMBER := dbms_utility.get_time;
        vv_sid              NUMBER;
        vv_do_log           CHAR;
        vv_name_interface   VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface     NUMBER;
        vv_id_codsystem     NUMBER;
--END INTERFACE VARIABLES


--PROGRAM VARIABLES
        dlt_trunk_id        NUMBER;
        pbx_cnt             NUMBER;
        ssh_message         VARCHAR2(100);
        ssh_result          NUMBER;
        vo_t_username       NUMBER := vi_t_username;
        vo_u2000_message    VARCHAR2(1000);
        vo_u2000_result     INT;
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA


  --FN_GET_TRUNK_U2000 Function CALL
        vo_u2000_result := pck_pbx.fn_get_trunk_u2000(vi_username, vi_password, vi_ip_info, vo_t_username, vo_u2000_message, vo_u2000_result
        );

        SELECT
            trunk_id
        INTO dlt_trunk_id
        FROM
            midware.hosted_pbx_u2000
        WHERE
            phone_num = vo_t_username
            AND deleted_at IS NULL;


    --ERROR Handling for FN_GET_TRUNK_U2000

        IF ( vo_u2000_result > 0 ) THEN
            vo_message := 'ERROR: Verify U2000 error code '
                          || vo_u2000_result
                          || ' for Trunk ID: '
                          || dlt_trunk_id;
            vo_result := vo_u2000_result;
            RETURN vo_result;
        ELSIF ( vo_u2000_result < 0 ) THEN
            vo_message := 'ERROR: '
                          || 'Trunk not found. Please verify if '
                          || vo_t_username
                          || ' exists in the Midware U2000 Table';
            vo_result := vo_u2000_result;
            RETURN vo_result;
        END IF;


  --Execute Delete on U2000

        ssh_message := pck_pbx.fn_ssh_connect(gv_delete_u2000
                                              || ' '
                                              || dlt_trunk_id);
        ssh_result := regexp_replace(ssh_message, '[^[:digit:]]', '');


    --ERROR Handling for U2000
        IF ( ssh_result > 0 ) THEN
            vo_message := regexp_replace(ssh_message, '[^a-z and ^A-Z]', '');
            vo_result := ssh_result;
            RETURN vo_result;
        END IF;

        UPDATE midware.hosted_pbx_u2000
        SET
            deleted_at = SYSDATE
        WHERE
            trunk_id = dlt_trunk_id
            AND deleted_at IS NULL;

        vo_message := 'SUCCESS';
        vo_result := 0;
        RETURN vo_result;


--GLOBAL EXCEPTION HANDLING
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            vo_result := -8000;
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_delete_trunk_u2000;

    FUNCTION fn_suspend_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER AS

    --INTERFACE VARIABLES

        vv_mid_id_user       NUMBER := 1;
        vv_log_message       VARCHAR2(2000);
        vv_exe_time          NUMBER := dbms_utility.get_time;
        vv_sid               NUMBER;
        vv_do_log            CHAR;
        vv_name_interface    VARCHAR2(50) := utl_call_stack.subprogram(1)(2);
        vv_id_interface      NUMBER;
        vv_id_codsystem      NUMBER;
    --END INTERFACE VARIABLES
    --FUNCTION VARIABLES
        vv_num               NUMBER := 1;
        vv_search_txt        VARCHAR2(100);
        vo_tenants           VARCHAR2(2000);
        --AUTHENTICATION VARIABLES
        auth_token           VARCHAR2(1000);
        auth_result          NUMBER;
        --END AUTHENTICATION VARIABLES        
        --FIND VARIABLES
        find_tenant_id       VARCHAR2(1000);
        find_result          NUMBER;
        find_http_status     VARCHAR2(100);
        --END FIND VARIABLES
        --SUS VARIALBLES
        sus_http_response    VARCHAR2(10000);
        sus_http_parameter   VARCHAR2(1000);
        sus_http_status      VARCHAR2(100);
        --END SUS VARIALBLES
    --END FUNCTION VARIABLES
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

        vv_mid_id_user := pck_middle.mid_interface_login(trim(vi_username), vi_password, vv_id_interface, vo_message, vo_result)

        ;

        IF ( vv_mid_id_user < 0 ) THEN
            vv_log_message := 'USER:'
                              || vi_username
                              || '||'
                              || vi_ip_info
                              || '||'
                              || vo_message;

            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, 1, vv_exe_time);

            RETURN vo_result;
        END IF;

        vv_log_message := vi_ip_info;
    --END INTERFACE DATA
        IF regexp_like(vi_t_username, '^[0-9]{7}$') THEN
            auth_result := fn_post_authenticate_tenant(vi_username, vi_password, vi_ip_info, auth_token, vo_message, vo_result);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||AUTH_RESULT||'|'||AUTH_TOKEN||'|'||AUTH_MESSAGE);
            find_result := fn_get_tenant(vi_username, vi_password, vi_ip_info, vi_t_username, vo_tenants, vo_message, vo_result);
        --dbms_output.put_line(to_char($$plsql_line)||'|'||VO_TENANTS);

            IF vo_result = 0 THEN
                vv_search_txt := '<ID>';
                vv_num := instr(vo_tenants, vv_search_txt, vv_num);
                find_tenant_id := TO_CHAR(substr(vo_tenants, vv_num + length(vv_search_txt), instr(vo_tenants, '</ID>', vv_num + length
                (vv_search_txt)) -(vv_num + length(vv_search_txt))));
            --DBMS_OUTPUT.PUT_LINE(to_char($$PLSQL_LINE)||':'||FIND_TENANT_ID);

                vv_search_txt := '<STATUS>';
                vv_num := instr(vo_tenants, vv_search_txt, vv_num);
                find_http_status := TO_CHAR(substr(vo_tenants, vv_num + length(vv_search_txt), instr(vo_tenants, '</STATUS>', vv_num
                + length(vv_search_txt)) -(vv_num + length(vv_search_txt))));
            --DBMS_OUTPUT.PUT_LINE(to_char($$PLSQL_LINE)||':'||FIND_HTTP_STATUS);

                IF find_http_status != 'running' THEN
                    vo_result := -4020;
                    vo_message := 'Error: Tenant already stopped';
                ELSE
                    sus_http_parameter := '{"action":"stop-tenant", "id":"'
                                          || find_tenant_id
                                          || '",'
                                          || '"token":"'
                                          || auth_token
                                          || '"}';

                    midware.mid_http_post(gv_http_tenant_url, sus_http_parameter, 'application/json', sus_http_status, sus_http_response

                    );
                --dbms_output.put_line(to_char($$plsql_line)||'|'||SUS_HTTP_STATUS||'|'||SUS_HTTP_RESPONSE);
                    IF sus_http_status != 200 THEN
                        vo_result := -4021;
                        vo_message := 'Error: Unable to stop tenant';
                    ELSE
                        vo_result := 0;
                        vo_message := 'Stopping Tenant';
                    END IF;

                END IF;

            END IF;

        ELSE
            SELECT
                'Error: Username must be 7 digit numeric value'
            INTO vo_message
            FROM
                dual;

            vo_result := -2001;
        END IF;

        pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time

        );

        RETURN vo_result;
    EXCEPTION
        WHEN OTHERS THEN
            vo_result := -8000;
            vo_message := 'Contact BTL MIDWARE ADMIN';
            vv_log_message := 'ERROR:'
                              || vv_log_message
                              || '|'
                              || sqlerrm;
            pck_middle.mid_log_execution(vv_sid, SYSDATE, vv_log_message, vv_id_interface, vv_id_codsystem, vv_mid_id_user, vv_exe_time
            );

            pck_middle.mid_log_error(vv_sid, SYSDATE, vv_id_interface, vv_id_codsystem, sqlerrm, dbms_utility.format_error_stack

            , dbms_utility.format_call_stack || dbms_utility.format_error_backtrace);--store the errors or present all errors found.

            RETURN vo_result;
    END fn_suspend_subscriber;

FUNCTION fn_ssh_connect (
    inputs IN VARCHAR2
) RETURN VARCHAR2 AS LANGUAGE JAVA NAME 'SshConnection.SshConnect (java.lang.String) return java.lang.String';END pck_pbx;
