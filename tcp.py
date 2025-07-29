import asyncio
import math
from tcputils import *


class Servidor:
    # Nao mudar
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            print(f'Porta de destino {dst_port} não corresponde à porta do servidor {self.porta}.')
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('Segmento descartado devido a checksum incorreto')
            return

        header_length = 4 * (flags >> 12)
        payload = segment[header_length:]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) and id_conexao not in self.conexoes:
            print(f'Recebido SYN de {src_addr}:{src_port}, criando nova conexão.')
            conexao = Conexao(self, id_conexao, seq_no)
            self.conexoes[id_conexao] = conexao

            # Preparar resposta SYN-ACK
            ack_no = seq_no + 1
            syn_ack_header = make_header(dst_port, src_port, seq_no, ack_no, FLAGS_SYN | FLAGS_ACK)
            syn_ack_segment = fix_checksum(syn_ack_header, src_addr, dst_addr)
            self.rede.enviar(syn_ack_segment, src_addr)

            if self.callback:
                print('Notificando o callback sobre a nova conexão aceita.')
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            print(f'Pacote associado à conexão existente: {id_conexao}')
            conexao = self.conexoes[id_conexao]
            conexao._rdt_rcv(seq_no, ack_no, flags, payload)

        else:
            print(f'Pacote de {src_addr}:{src_port} para {dst_addr}:{dst_port} associado a conexão desconhecida.')



class Conexao:
    def __init__(self, servidor, id_conexao, seq_inicial):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_inicial = seq_inicial
        self.prox_seq = seq_inicial + 1
        self.prox_ack = seq_inicial + 1
        self.callback = None
        self.timer = None
        self.dados_nao_confirmados = b''  

    def handle_timeout(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None 

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        if self.dados_nao_confirmados:
            header = make_header(dst_port, src_port, self.seq_inicial, self.prox_ack, FLAGS_ACK)
            segment = fix_checksum(header + self.dados_nao_confirmados[:MSS], dst_addr, src_addr)
            self.servidor.rede.enviar(segment, src_addr)
            print(f'Reenviando pacote: Seq={self.seq_inicial}, Tam={len(self.dados_nao_confirmados[:MSS])}')

        self.timer = asyncio.get_event_loop().call_later(1, self.handle_timeout)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        print(f'Recebido payload: {payload}')

        if self.prox_ack != seq_no:
            return

        if flags & FLAGS_FIN:
            self.prox_ack += 1
            fin_ack_header = make_header(dst_port, src_port, self.seq_inicial, self.prox_ack, FLAGS_ACK)
            fin_ack_segment = fix_checksum(fin_ack_header, dst_addr, src_addr)
            self.servidor.rede.enviar(fin_ack_segment, src_addr)
            self.callback(self, b'')
            del self.servidor.conexoes[self.id_conexao]

        self.prox_ack += len(payload)

        if payload:
            ack_header = make_header(dst_port, src_port, self.seq_inicial, self.prox_ack, FLAGS_ACK)
            ack_segment = fix_checksum(ack_header, dst_addr, src_addr)
            self.callback(self, payload)
            self.servidor.rede.enviar(ack_segment, src_addr)
            return

        if flags & FLAGS_ACK:
            if self.timer:
                self.timer.cancel()
                self.timer = None

            self.dados_nao_confirmados = self.dados_nao_confirmados[ack_no - self.seq_inicial:]
            self.seq_inicial = ack_no

            if ack_no < self.prox_seq:
                self.timer = asyncio.get_event_loop().call_later(0.5, self.handle_timeout)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        offset = 0
        while offset < len(dados):
            payload = dados[offset:offset + MSS]
            header = make_header(dst_port, src_port, self.prox_seq, self.prox_ack, FLAGS_ACK)
            segment = fix_checksum(header + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(segment, src_addr)
            print(f'Enviando pacote: Seq={self.prox_seq}, Tam={len(payload)}')

            # Atualiza o número de sequência e os dados não reconhecidos
            self.prox_seq += len(payload)
            self.dados_nao_confirmados += payload
            offset += MSS

            # Inicia o temporizador de timeout se não estiver rodando
            if not self.timer:
                self.timer = asyncio.get_event_loop().call_later(0.5, self.handle_timeout)

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        fin_header = make_header(dst_port, src_port, self.prox_seq, self.prox_ack, FLAGS_FIN)
        fin_segment = fix_checksum(fin_header, dst_addr, src_addr)

        self.servidor.rede.enviar(fin_segment, src_addr)
        print(f'Enviando FIN: Seq={self.prox_seq}, Ack={self.prox_ack}')

        if not self.timer:
            self.timer = asyncio.get_event_loop().call_later(1, self.handle_timeout)
