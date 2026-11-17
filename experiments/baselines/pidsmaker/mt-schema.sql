-- Schema of PIDSMaker database mt (pg_dump -s --no-owner --no-privileges on the test host, 2026-11-11;
-- originally cloned from theia_e3). Used by experiments/heldout/run_baselines_aws.sh on a fresh postgres.
--
-- PostgreSQL database dump
--

\restrict yfyFQMJTfDP95pdTufFp3wJnRz300KDxdffueAyRI6RMflJtGhS5pPFzhG8K2QT

-- Dumped from database version 17.11 (Debian 17.11-1.pgdg13+2)
-- Dumped by pg_dump version 17.11 (Debian 17.11-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: event_table; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_table (
    src_node character varying,
    src_index_id character varying,
    operation character varying,
    dst_node character varying,
    dst_index_id character varying,
    event_uuid character varying NOT NULL,
    timestamp_rec bigint,
    _id integer NOT NULL
);


--
-- Name: event_table__id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_table__id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_table__id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_table__id_seq OWNED BY public.event_table._id;


--
-- Name: file_node_table; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_node_table (
    node_uuid character varying NOT NULL,
    hash_id character varying NOT NULL,
    path character varying,
    index_id bigint
);


--
-- Name: netflow_node_table; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.netflow_node_table (
    node_uuid character varying NOT NULL,
    hash_id character varying NOT NULL,
    src_addr character varying,
    src_port character varying,
    dst_addr character varying,
    dst_port character varying,
    index_id bigint
);


--
-- Name: subject_node_table; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subject_node_table (
    node_uuid character varying NOT NULL,
    hash_id character varying NOT NULL,
    path character varying,
    cmd character varying,
    index_id bigint
);


--
-- Name: event_table _id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_table ALTER COLUMN _id SET DEFAULT nextval('public.event_table__id_seq'::regclass);


--
-- Name: file_node_table file_node_table_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_node_table
    ADD CONSTRAINT file_node_table_pk PRIMARY KEY (node_uuid, hash_id);


--
-- Name: netflow_node_table netflow_node_table_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.netflow_node_table
    ADD CONSTRAINT netflow_node_table_pk PRIMARY KEY (node_uuid, hash_id);


--
-- Name: subject_node_table subject_node_table_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subject_node_table
    ADD CONSTRAINT subject_node_table_pk PRIMARY KEY (node_uuid, hash_id);


--
-- Name: event_table__id_uindex; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX event_table__id_uindex ON public.event_table USING btree (_id);


--
-- PostgreSQL database dump complete
--

\unrestrict yfyFQMJTfDP95pdTufFp3wJnRz300KDxdffueAyRI6RMflJtGhS5pPFzhG8K2QT

