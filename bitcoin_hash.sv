module bitcoin_hash (input logic clk, reset_n, start, 
                     input logic [15:0] message_addr, output_addr, 
							output logic done, mem_clk, mem_we, 
							output logic [15:0] mem_addr, 
							output logic [31:0] mem_write_data, 
							input logic [31:0] mem_read_data); 
  
    // SHA256 K constants 
  parameter int sha256_k[0:63] = '{ 
     32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5, 
	  32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174, 
	  32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da, 
	  32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967, 
	  32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85, 
	  32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070, 
	  32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3, 
	  32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2 
  }; 
  
  // SHA256 hash round
  function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                   input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
  begin
      S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
      ch = (e & f) ^ ((~e) & g);
      t1 = h + S1 + ch + sha256_k[t] + w;
      S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
      maj = (a & b) ^ (a & c) ^ (b & c);
      t2 = S0 + maj;

      sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
  end
  endfunction

  // right rotation
  function logic [31:0] rrot (input logic [31:0] x,
                              input logic [7:0] r);
  begin
    rrot = (x >> r) | (x << (32-r));
  end
  endfunction
 
  //define states here
  enum logic [3:0] {IDLE=4'b0000, READ0=4'b0001, READ1=4'b0010, COMPUTEFIRSTBLOCK=4'b0011, FIRSTBLOCKCONT=4'b0100, FIRSTBLOCKRESULTS=4'b0101, 
					     READSECOND0=4'b0110, READSECOND1=4'b0111, READSECOND2=4'b1000, SHAUNDER16=4'b1001, SHAOVER16=4'b1010, 
						  FIRSTHASH=4'b1011, WRITE=4'b1100} state;
  

  //memory clock is normal clock
  assign mem_clk = clk;
  
  logic [31:0] w[0:15];
  logic [31:0] H[0:7];
  logic [31:0] end1, end2, end3;
  logic [31:0] nonce;
  logic [31:0] a, b, c, d, e, f, g, h;
  logic [31:0] wtxnew;
  logic [7:0] rc, wc, t, i;
  logic [1:0] isSecond;
 
   //wtnew
	function logic [31:0] wtnew; // function with no inputs 
	begin
	  logic [31:0] s0, s1; 
	  s0 = rrot(w[1],7)^rrot(w[1],18)^(w[1]>>3); 
	  s1 = rrot(w[14],17)^rrot(w[14],19)^(w[14]>>10); 
	  wtnew = w[0] + s0 + w[9] + s1; 
	end
	endfunction
  
  always_ff @(posedge clk, negedge reset_n)
  begin
    if (!reset_n) begin
		state <= IDLE;
    end else
      case (state)
        IDLE:
          if (start) begin
				{H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
			   mem_addr <= message_addr; 
				mem_we <= 0;
				rc <= 1;
				wc <= 0;
				isSecond <= 0;
				done <= 0;
            state <= READ0;
          end
        READ0: begin
			 mem_addr <= message_addr + rc; 
			 rc <= rc + 1; 
		    state <= READ1;
		  end
		  READ1: begin
		    w[15] <= mem_read_data; 
			 mem_addr <= message_addr + rc; 
			 rc <= rc + 1; 
			 t = 0;
			 a <= H[0]; b <= H[1]; c <= H[2]; d <= H[3]; e <= H[4]; f <= H[5]; g <= H[6]; h <= H[7];
		    state <= COMPUTEFIRSTBLOCK;
		  end
		  COMPUTEFIRSTBLOCK: begin
		    {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], t); 
			 for( i = 0; i < 15; i++ ) w[i] <= w[i+1];
			 if (t < 15 ) w[15] <= mem_read_data;
			 else w[15] <= wtnew(); 
			 if( rc < 16 ) begin 
			   mem_addr <= message_addr + rc; 
			   rc <= rc + 1; 
			 end
			 t = t + 1;
			 if( t > 62 ) state <= FIRSTBLOCKCONT;
		  end
		  FIRSTBLOCKCONT: begin
		    {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], t);
			 mem_addr <= message_addr + rc;
			 rc <= rc + 1;
			 state <= FIRSTBLOCKRESULTS;
		  end
		  FIRSTBLOCKRESULTS: begin
		    H[0] <= H[0] + a; H[1] <= H[1] + b; H[2] <= H[2] + c; H[3] <= H[3] + d; H[4] <= H[4] + e; H[5] <= H[5] + f; H[6] <= H[6] + g; H[7] <= H[7] + h;
			 t = 0;
			 mem_addr <= message_addr + rc; 
			 rc <= rc + 1;
			 state <= READSECOND0;
		  end
		  READSECOND0: begin
		    a <= H[0]; b <= H[1]; c <= H[2]; d <= H[3]; e <= H[4]; f <= H[5]; g <= H[6]; h <= H[7];
		    mem_addr <= message_addr + rc; 
			 end1 <= mem_read_data;
			 rc <= rc + 1;
			 w[0] <= mem_read_data;
			 state <= READSECOND1;
		  end
		  READSECOND1: begin
		    mem_addr <= message_addr + rc;
			 end2 <= mem_read_data;
			 w[1] <= mem_read_data; 
			 state <= READSECOND2;
		  end
		  READSECOND2: begin
		    end3 <= mem_read_data;
			 w[2] <= mem_read_data;
			 nonce <= 0;
			 w[3] <= 0;
			 w[4] <= 32'h80000000;
			 for (i = 5; i < 15; i++) w[i] <= 32'h00000000;
			 w[15] <= 32'd640;
			 state <= SHAUNDER16;
		  end
		  SHAUNDER16: begin
		    {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[t], t); 
			 t = t + 1;
			 if( t > 15 ) state <= SHAOVER16;
		  end
		  SHAOVER16: begin  
			 for (i = 0; i < 15; i++) w[i] <= w[i+1];
			 wtxnew = wtnew();
			 w[15] <= wtxnew; 
			 {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wtxnew, t);
			 t = t + 1;
			 if( t > 63 ) begin 
			   state <= FIRSTHASH;
				if( isSecond == 1 ) state <= WRITE;
			 end
		  end
		  FIRSTHASH: begin
		    w[0] <= H[0] + a; w[1] <= H[1] + b; w[2] <= H[2] + c; w[3] <= H[3] + d; w[4] <= H[4] + e; w[5] <= H[5] + f; w[6] <= H[6] + g; w[7] <= H[7] + h;
			 w[8] <= 32'h80000000;
			 for (i = 9; i < 15; i++) w[i] <= 32'h00000000;
			 w[15] <= 32'd256;
			 {a,b,c,d,e,f,g,h} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
			 t = 0; 
			 isSecond <= 1;
			 state <= SHAUNDER16;
		  end
		  WRITE: begin
		   //here is where we'd get all the H's for each nonce, but for this proj we only need H0 for each nonce
			mem_we <= 1;
		   mem_addr <= output_addr + wc;
			wc <= wc + 1;
			mem_write_data <= a + 32'h6a09e667;
			if( nonce > 15 ) done <= 1;
			a <= H[0]; b <= H[1]; c <= H[2]; d <= H[3]; e <= H[4]; f <= H[5]; g <= H[6]; h <= H[7];
			w[0] <= end1; w[1] <= end2; w[2] <= end3; 
			w[3] <= nonce + 1;
			w[4] <= 32'h80000000;
			for (i = 5; i < 15; i++) w[i] <= 32'h00000000;
			w[15] <= 32'd640;
			isSecond <= 0;
			nonce <= nonce + 1;
			t = 0;
			state <= SHAUNDER16;
		  end
      endcase
  end
endmodule
