`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: AHU
// Engineer: 52funny 
//////////////////////////////////////////////////////////////////////////////////


module main(
    input sys_clk_p,
    input sys_clk_n,
    input rst_n,
    input uart_rx,
    output uart_tx
);

parameter       CLK_FRE = 200;

wire sys_clk;

wire[7:0] rx_data;
wire rx_data_valid;
wire rx_data_ready;
reg[3:0] rx_cnt;		      // max 0xf



reg[7:0] tx_data;
reg tx_data_valid;
wire tx_data_ready;
reg[3:0] tx_cnt;		      // max 0xf


reg[95:0] challenge;		  // challenge
reg[95:0] response;           // response


assign rx_data_ready = 1'b1;	// always ready for rx

// assign tx_data = response[7:0];

IBUFDS IBUFDS_inst(
    .O(sys_clk),
    .I(sys_clk_p),
    .IB(sys_clk_n)
);

uart_rx#(
    .CLK_FRE(CLK_FRE),
    .BAUD_RATE(115200)
) uart_rx_inst(
    .clk            (sys_clk),
    .rst_n          (rst_n),
    .rx_data        (rx_data),
    .rx_data_valid  (rx_data_valid),
    .rx_data_ready  (rx_data_ready),
    .rx_pin         (uart_rx)
);


uart_tx#(
    .CLK_FRE(CLK_FRE),
    .BAUD_RATE(115200)
) uart_tx_inst(
    .clk            (sys_clk),
    .rst_n          (rst_n),
    .tx_data        (tx_data),
    .tx_data_valid  (tx_data_valid),
	.tx_data_ready  (tx_data_ready),
    .tx_pin         (uart_tx)
);

reg trig_i;
wire busy_o;
wire[95:0] id_o;

fpga_puf fpga_puf_inst(
	.clk_i(sys_clk),
	.rstn_i(rst_n),
	.trig_i(trig_i),
	.busy_o(busy_o),
	.id_o(id_o)
);

// RX State
localparam RX_IDLE = 1'b0;
localparam RX_RECV = 1'b1;
reg[1:0] rx_state;

// TX State
localparam TX_IDLE = 1'b0;
localparam TX_SEND = 1'b1;
reg[1:0] tx_state;

// PUF State
localparam PUF_IDLE = 4'd0;
localparam PUF_SIG = 4'd1;
localparam PUF_WAIT = 4'd2; 
reg[2:0] puf_state;

reg puf_enable;
reg tx_enable;

always @(posedge sys_clk or negedge rst_n)
begin
	if(!rst_n)
	begin
		puf_state <= PUF_IDLE;
	end
	else
		case(puf_state)
			PUF_IDLE:
			begin
				if(puf_enable)
					puf_state <= PUF_SIG;
				else
					puf_state <= PUF_IDLE;
				tx_enable <= 1'b0;
			end
			PUF_SIG:
				if(busy_o)
				begin
					puf_state <= PUF_WAIT;
					trig_i <= 1'b0;
				end
				else
					trig_i <= 1'b1;
			PUF_WAIT:
				if(~busy_o)
				begin
					puf_state <= PUF_IDLE;
					// enable tx
					tx_enable <= 1'b1;
				end
				else
					puf_state <= PUF_WAIT;
			default:
				puf_state <= PUF_IDLE;
		endcase
end



// rx state
always @(posedge sys_clk or negedge rst_n)
begin
	if(!rst_n)
	begin
		rx_state <= RX_IDLE;
		rx_cnt <= 4'd0;
		challenge <= 96'd0;
		puf_enable <= 1'b0;
	end
	else
			begin
				if(rx_data_valid && rx_data_ready)
				begin
					if (rx_cnt < 4'd11)
					begin
						challenge <= (challenge << 8) | rx_data;
						rx_cnt <= rx_cnt + 1'b1;
					end
					else
					begin
						challenge <= (challenge << 8) | rx_data;
						rx_cnt <= 4'd0;
						// enable puf working
						puf_enable <= 1'b1;
					end
				end
				else if (puf_state == PUF_IDLE) 
					puf_enable <= 1'b0;
			end
end

// tx state
always @(posedge sys_clk or negedge rst_n)
begin
	if(!rst_n)
	begin
		tx_state <= TX_IDLE;
		tx_cnt <= 4'd0;
		tx_data <= 8'd0;
		response <= 96'd0;
		tx_data_valid <= 1'b0;
	end
	else 
		case(tx_state)
			TX_IDLE:
			begin
				if(tx_enable)
				begin
					// response <= id_o;
					response <= id_o ^ challenge;
					tx_state <= TX_SEND;
				end
				else
					tx_state <= TX_IDLE;
			end
			TX_SEND:
			begin
				if(tx_data_valid && tx_data_ready)
				begin
					if (tx_cnt < 4'd12)
					begin
						tx_data <= response[95:88];
						response <= (response << 8);
						tx_cnt <= tx_cnt + 1'b1;
					end
					else
					begin
						tx_cnt <= 4'd0;
						tx_state <= TX_IDLE;
						tx_data_valid <= 1'b0;
					end
				end
				else if (~tx_data_valid)
				begin
					tx_data <= response[95:88];
					response <= (response << 8);
					tx_cnt <= tx_cnt + 1'b1;
					tx_data_valid <= 1'b1;
				end
			end
			default:
				tx_state <= TX_IDLE;
		endcase
end

endmodule
