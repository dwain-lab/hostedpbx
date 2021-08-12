CREATE OR REPLACE PACKAGE PCK_PBX AS
-- --------------------------------------------------------------------------
-- Name         : PCK_PBX
-- Author       : 
-- Description  : Package for Hosted PBX
-- Requirements : PCK_MIDDLE
-- License      : The contents of this document can only be derived rights against Belize Telemedia Limited
--                if they are supported by duly signed documents. The information may be confidential and 
--                only for use by the addressee (s). If you have this document unjustly in your possession,
--                you are requested to destroy it. It is not allowed to revise this document or parts thereof,
--                copying or use outside of its context.
-- Amendments   :
--   When         Who                   What
--   ===========  ===============       =================================================
--   25-May-2021  Zane Gibson           Initial Creation
--   25-May-2021  Aaron Stevens         Added function FN_POST_AUTHENTICATE
--   27-May-2021  Dwain Wagner            Add:
--                                          *fn_add_subscriber - add subscriber to pbx
--   31-May-2021  Dwain Wagner            Add:
--                                          *fn_find_trunk - find trunk to complete pbx
--   03-Jun-2021  Dwain Wagner            Add:
--                                          *fn_add_tenant - add tenant to MultiTenant Manager
--   04-Jun-2021  Keenan Bernard        Added function FN_DELETE_SUBSCRIBER
--   04-Jun-2021  Aaron Stevens         Added function FN_UPDATE_SUBSCRIBER
--   08-Jun-2021  Aaron Stevens         Added function FN_POST_AUTHENTICATE_TENANT
--   08-Jun-2021  Keenan Bernard        Added function FN_GET_TENANTS
--   10-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS
--   10-Jun-2021  Aaron Stevens         Updated function FN_GET_RESOURCE_PLANS_ID
--   14-Jun-2021  Aaron Stevens         Added function FN_UPDATE_TENANT
--   28-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS - Numeric Validation
--   29-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS - Plan Name
--   01-Jul-2021  Zane Gibson           Updated function FN_ADD_SUBSCRIBER:
--                                      i) Updated PBX Image value and added whitelisting element to allow CPBX provisioning from Middleware
--                                      ii) Add input validation for trunk 
--   01-Jul-2021  Keenan Bernard        Updated function FN_DELETE_SUBSCRIBER - Numeric Validation 
--   05-Jul-2021  Keenan Bernard        Updated function FN_DELETE_TENANT - Numeric Validation
--   09-Jul-2021  Dwain Wagner          Add:
--                                          1) FN_SSH_CONNECT - Allow system to connect to remotely via ssh and perform an action
--   14-Jul-2021  Aaron Stevens         Updated function FN_UPDATE_SUBSCRIBER- Numeric Validation 
--   14-Jul-2021  Aaron Stevens         Added function FN_UPDATE_TRUNK_U2000_MIDDB
--   14-Jul-2021  Keenan Bernard        Added function FN_DELETE_TRUNK_U2000
--   16-Jul-2021  Keenan Bernard        Update of Error Codes
--   19-Jul-2021  Dwain Wagner          Update of Error Codes and Password
--   19-Jul-2021  Keenan Bernard        Update function FN_GET_TENANTS - Status & DID output
--   26-Jul-2021  Keenan Bernard        Update function FN_GET_TENANTS - Status output
--   04-Aug-2021  Dwain Wagner          Add:
--                                          *fn_reconnect_subscriber - Start Tenant on the Multi Tenant System
--   09-Aug-2021  Aaron Stevens         Added function FN_SUSPEND_SUBSCRIBER
-- -------------------------------------------------------------------------------
    
    GV_CODSYSTEM             VARCHAR2(20)  :='HOSTED'; 
--Complete PBX
    GV_HTTP_URL              VARCHAR2(200):='pbx.btl.net/api';
    GV_KEY                   VARCHAR2(200):='btl_prov_eo9i7q3yzu8j6q0rkkcj9iatvk7y64rk4aus9mvm';
    GV_OUTGOING_HOST         VARCHAR2(20)  := 'ims.btl.net';
    GV_OUTGOING_FROMDOMAIN   VARCHAR2(20)  := 'ims.btl.net';
    GV_OUTBOUND_PROXY        VARCHAR2(20)  := '172.26.3.227';
    GV_OUTGOING_INSECURE     VARCHAR2(20)  := 'port,invite';
    GV_OUTGOING_TYPE         VARCHAR2(1)   := '1';   --Allow inbound calls
    GV_OUTGOING_PORT         NUMBER        := 5060;
--MultiTenant Manager
    GV_HTTP_TENANT_URL       VARCHAR2(200):='https://pbx.btl.net/api';
    GV_URL                   VARCHAR2(200) :='https://devtest.pbx.btl.net/api/authenticate';
    GV_PLAN_S                VARCHAR2(50)  := '334c21fe-b4a1-284f-d60e-a4838bae3eb4';
    GV_PLAN_M                VARCHAR2(50)  := '33331b55-6306-d7bb-ba5b-a7cb2aebd479';
    GV_PLAN_L                VARCHAR2(50)  := 'd4c7a3cb-2658-e2ca-8977-92b8c90abe12';
--U2000
    GV_GET_U2000             VARCHAR2(50)  := 'get_telnet_1.sh';
    GV_ADD_U2000             VARCHAR2(50)  := 'add_telnet_1.sh';
    GV_UPDATE_U2000          VARCHAR2(50)  := 'update_telnet_1.sh';
    GV_DELETE_U2000          VARCHAR2(50)  := 'remove_telnet_1.sh';


    FUNCTION FN_POST_AUTHENTICATE (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2,vi_t_username VARCHAR2, VO_TOKEN OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_ADD_TRUNK_CPBX (VI_USERNAME IN VARCHAR2, VI_PASSWORD IN VARCHAR2, VI_IP_INFO IN VARCHAR2, VI_T_USERNAME IN VARCHAR2, VI_T_PASSWORD IN VARCHAR2, VI_PRODUCT IN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT NUMBER )
    RETURN NUMBER;

    FUNCTION FN_FIND_TRUNK (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_PRODUCT VARCHAR2, VO_TRUNK_ID OUT NUMBER, VO_T_USERNAME  OUT VARCHAR2, VO_T_PASSWORD  OUT VARCHAR2, VO_RESULT OUT  NUMBER, VO_MESSAGE OUT  VARCHAR2)
    RETURN NUMBER;

    FUNCTION FN_ADD_SUBSCRIBER (VI_USERNAME VARCHAR2, VI_PASSWORD    VARCHAR2, VI_IP_INFO     VARCHAR2, VI_T_USERNAME  VARCHAR2, VI_PLAN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_GET_TENANT_ID (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_NUMBER VARCHAR2, VO_TENANTS_ID OUT VARCHAR2, VO_TENANT_RESOURCE_ID OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_ADD_DID (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_DID_NUMBER VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT NUMBER) 
    RETURN NUMBER;

    FUNCTION FN_UPDATE_SUBSCRIBER (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VI_T_NEW_PASSWORD VARCHAR2, VI_PRODUCT IN VARCHAR2, VO_RESULT OUT NUMBER, VO_MESSAGE OUT VARCHAR2)
    RETURN NUMBER;

    FUNCTION FN_POST_AUTHENTICATE_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VO_T_TOKEN OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_DELETE_SUBSCRIBER (VI_USERNAME IN VARCHAR2, VI_PASSWORD IN VARCHAR2, VI_IP_INFO IN VARCHAR2, VI_T_USERNAME IN VARCHAR2, VI_PRODUCT IN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT INT)
    RETURN NUMBER;

    FUNCTION FN_GET_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_NUMBER VARCHAR2, VO_TENANTS OUT VARCHAR2,VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_GET_RESOURCE_PLAN_ID (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_PLAN_NAME VARCHAR2, VO_RESOURCE_PLAN_ID OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_GET_RESOURCE_PLAN_NM (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_RESOURCE_PLAN_ID VARCHAR2, VO_PLAN_NM OUT VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_UPDATE_TENANT (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME  VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VI_PLAN_NAME VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_DELETE_TENANT(VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VO_MESSAGE OUT  VARCHAR2, VO_RESULT OUT NUMBER)
    RETURN NUMBER;

    FUNCTION FN_DELETE_DID(VI_USERNAME VARCHAR2,VI_PASSWORD VARCHAR2,VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_DID_NUMBER VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER) 
    RETURN NUMBER;

    FUNCTION FN_UPDATE_TRUNK_U2000_MIDDB (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VI_T_NEW_USERNAME VARCHAR2, VO_RESULT OUT NUMBER, VO_MESSAGE OUT VARCHAR2)
    RETURN NUMBER;

    FUNCTION fn_get_trunk_u2000
    (
        vi_username    VARCHAR2,
        vi_password    VARCHAR2,
        vi_ip_info     VARCHAR2,
        vi_t_username  VARCHAR2,
        vo_message     OUT  VARCHAR2,
        vo_result      OUT  NUMBER

    ) RETURN NUMBER;

    FUNCTION fn_add_trunk_u2000
    (
        vi_username    VARCHAR2,
        vi_password    VARCHAR2,
        vi_ip_info     VARCHAR2,
        vi_t_username  VARCHAR2,
        vo_message     OUT  VARCHAR2,
        vo_result      OUT  NUMBER

    ) RETURN NUMBER;

    FUNCTION fn_add_trunk_helper_cpbx ( 
        vi_username    IN   VARCHAR2, 
        vi_password    IN   VARCHAR2,
        vi_ip_info     IN   VARCHAR2,
        vi_t_username  IN   VARCHAR2,
        vi_t_password  IN   VARCHAR2,
        vi_product     IN   VARCHAR2,
        vo_message     OUT  VARCHAR2,
        vo_result      OUT  NUMBER  
    ) RETURN NUMBER;

    FUNCTION fn_reconnect_subscriber
    (
        vi_username    VARCHAR2,
        vi_password    VARCHAR2,
        vi_ip_info     VARCHAR2,
        vi_t_username  VARCHAR2,
        vo_message     OUT  VARCHAR2,
        vo_result      OUT  NUMBER

    ) RETURN NUMBER;

    FUNCTION FN_SSH_CONNECT (INPUTS VARCHAR2)
    RETURN VARCHAR2;

   FUNCTION FN_DELETE_TRUNK_U2000 (VI_USERNAME IN VARCHAR2, VI_PASSWORD IN VARCHAR2, VI_IP_INFO IN VARCHAR2, VI_T_USERNAME IN VARCHAR2, VO_MESSAGE OUT VARCHAR2, VO_RESULT OUT INT) 
   RETURN NUMBER;

   FUNCTION FN_SUSPEND_SUBSCRIBER (VI_USERNAME VARCHAR2, VI_PASSWORD VARCHAR2, VI_IP_INFO VARCHAR2, VI_T_USERNAME VARCHAR2, VO_MESSAGE OUT VARCHAR2,VO_RESULT OUT NUMBER)
   RETURN NUMBER;

END PCK_PBX;